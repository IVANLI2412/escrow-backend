//! Pull requests that close bountied issues: track them, trigger reviews, and start the payout on merge.

use crate::ports::ReviewScheduler;
use escrow_core::refs::parse_closing_refs;
use escrow_db::{Db, bounties, github, prs};
use escrow_github::{GithubApi, payloads::PullRequestEvent};
use escrow_payouts::{PayoutDeps, on_merge};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct PullDeps {
    pub db: Db,
    pub payouts: PayoutDeps,
    pub reviews: Option<Arc<dyn ReviewScheduler>>,
    /// quiet period before a review starts, so a burst of pushes costs one review
    pub review_delay: Duration,
}

const REVIEW_ACTIONS: [&str; 5] = ["opened", "synchronize", "reopened", "ready_for_review", "edited"];

/// Returns the bounty ids the PR is linked to. Never lets the maintainer's own PRs earn their bounty
/// (the contract blocks that too), and never reopens the record of a merged PR.
pub async fn handle_pull_request(d: &PullDeps, ev: &PullRequestEvent) -> Result<Vec<i64>, crate::EngineError> {
    let pr = &ev.pull_request;
    if pr.user.kind == "Bot" {
        return Ok(vec![]);
    }
    // Once merged the record is frozen: never relink, unlink or re-review it.
    if prs::get(&d.db.pool, pr.id).await?.is_some_and(|p| p.state == "merged") {
        return Ok(vec![]);
    }
    let repo_id = ev.repository.id;
    let issues: Vec<i32> =
        parse_closing_refs(pr.body.as_deref(), &repo_name(ev)).into_iter().filter_map(|n| i32::try_from(n).ok()).collect();

    // Drop links whose closing reference is gone. Only while the PR is unmerged, and only on the events
    // that can change what it closes (an edit to the body, or a synchronize that may rewrite it). A merged
    // PR's links are frozen (handled above); other actions never remove a still-pending submission. Only
    // live bounties are considered, so a link to an already-resolved bounty is left as history.
    if !pr.merged && matches!(ev.action.as_str(), "edited" | "synchronize") {
        let referenced: std::collections::HashSet<i32> = issues.iter().copied().collect();
        for b in prs::live_bounties(&d.db.pool, pr.id).await? {
            if b.repo_id == repo_id && !referenced.contains(&b.issue_number) {
                prs::unlink(&d.db.pool, pr.id, b.id).await?;
            }
        }
    }

    let live = bounties::active_for_issues(&d.db.pool, repo_id, &issues).await?;
    let eligible: Vec<_> = live.into_iter().filter(|b| b.maintainer_github_id != Some(pr.user.id)).collect();
    if eligible.is_empty() {
        return Ok(vec![]);
    }
    let state = if pr.merged {
        "merged"
    } else if pr.state == "closed" {
        "closed"
    } else {
        "open"
    };
    prs::upsert(
        &d.db.pool,
        &prs::PrUpsert {
            id: pr.id,
            number: pr.number,
            author_github_id: pr.user.id,
            author_login: &pr.user.login,
            head_sha: &pr.head.sha,
            state,
            merged_at: pr.merged_at,
        },
    )
    .await?;
    // one PR can close several bountied issues: one link per (PR, bounty)
    for b in &eligible {
        prs::link(&d.db.pool, pr.id, b.id).await?;
        if pr.merged && ev.action == "closed" {
            on_merge(&d.payouts, b.id, pr.number, pr.user.id).await?;
        }
    }
    if !pr.merged
        && state == "open"
        && !pr.draft
        && REVIEW_ACTIONS.contains(&ev.action.as_str())
        && (ev.action != "edited" || ev.changes.as_ref().is_some_and(|c| c.affects_review()))
        && let Some(r) = &d.reviews
        && github::ai_reviews_enabled(&d.db.pool, ev.repository.id).await?
    {
        // best effort: a scheduling hiccup must not fail the webhook
        if let Err(e) = r.schedule(pr.id, d.review_delay, false).await {
            tracing::warn!(pr = pr.id, error = %e, "could not schedule a review");
        }
    }
    Ok(eligible.iter().map(|b| b.id).collect())
}

/// What one pass of [`recover_missed_merges`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeSweep {
    /// PRs asked about on GitHub
    pub checked: usize,
    /// PR ids found merged whose payout was started (or found already started)
    pub merged: Vec<i64>,
    /// PR ids found closed without a merge
    pub closed: Vec<i64>,
    /// where the next pass continues; `None` once the whole set has been walked
    pub next_after: Option<i64>,
}

/// Catches merges whose `pull_request` webhook never arrived (the backend was down longer than GitHub retries,
/// or the App was suspended). Asks GitHub about up to `limit` open PRs linked to live bounties, oldest first and
/// after `after_id`, and sends any it finds merged through the same [`on_merge`] path as the webhook, so a merge
/// seen twice still pays once. A PR closed without merging is recorded as closed. Stops early on a GitHub rate limit.
pub async fn recover_missed_merges(
    d: &PullDeps,
    gh: &dyn GithubApi,
    after_id: Option<i64>,
    limit: i64,
) -> Result<MergeSweep, crate::EngineError> {
    let candidates = prs::open_linked_to_live(&d.db.pool, after_id, limit).await?;
    let mut out = MergeSweep {
        next_after: if candidates.len() as i64 >= limit { candidates.last().map(|p| p.id) } else { None },
        ..Default::default()
    };
    for c in candidates {
        let live = match gh.get_pull(c.installation_id, &c.repo_full_name, c.number).await {
            Ok(p) => p,
            Err(e) if e.retry_at().is_some() => {
                // rate limited: pick up from this PR next time instead of burning the rest of the budget
                tracing::warn!(pr = c.id, error = %e, "merge recovery paused by a GitHub rate limit");
                out.next_after = Some(c.id - 1);
                break;
            }
            Err(e) => {
                tracing::warn!(pr = c.id, repo = %c.repo_full_name, error = %e, "could not check a PR for a missed merge");
                continue;
            }
        };
        out.checked += 1;
        if live.merged {
            // start the payout before freezing the record, so a failure here is retried by the next pass
            for b in prs::live_bounties(&d.db.pool, c.id).await? {
                if b.maintainer_github_id != Some(c.author_github_id) {
                    on_merge(&d.payouts, b.id, c.number, c.author_github_id).await?;
                }
            }
            prs::upsert(&d.db.pool, &upsert_from(&c, &live.head.sha, "merged", live.merged_at)).await?;
            tracing::info!(pr = c.id, repo = %c.repo_full_name, number = c.number, "recovered a merge whose webhook was missed");
            out.merged.push(c.id);
        } else if live.state == "closed" {
            prs::upsert(&d.db.pool, &upsert_from(&c, &live.head.sha, "closed", None)).await?;
            out.closed.push(c.id);
        }
    }
    Ok(out)
}

fn upsert_from<'a>(
    c: &'a prs::OpenLinked,
    head_sha: &'a str,
    state: &'a str,
    merged_at: Option<chrono::DateTime<chrono::Utc>>,
) -> prs::PrUpsert<'a> {
    prs::PrUpsert {
        id: c.id,
        number: c.number,
        author_github_id: c.author_github_id,
        author_login: &c.author_login,
        head_sha,
        state,
        merged_at,
    }
}

fn repo_name(ev: &PullRequestEvent) -> String {
    ev.repository.full_name.clone()
}
