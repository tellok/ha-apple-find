const VERSION_BRANCH = "release/version-update";
const MARKER = "<!-- ci-toolkit:version-pr -->";
const SHA = /^[a-f0-9]{40}$/;

function sameRepository(pr, repository) {
  return pr.head.repo?.full_name === repository && pr.base.repo?.full_name === repository;
}

function managed(pr, repository, defaultBranch) {
  return sameRepository(pr, repository)
    && pr.head.ref === VERSION_BRANCH
    && pr.base.ref === defaultBranch
    && pr.body?.includes(MARKER);
}

async function resolvePR(github, context, core) {
  const fresh = context.eventName === "workflow_dispatch";
  const event = context.payload;
  const request = fresh ? event.inputs : {
    pr: String(event.pull_request.number),
    head: event.pull_request.head.sha,
    base: event.pull_request.base.sha,
    target: event.pull_request.base.ref,
  };
  if (!/^[1-9][0-9]*$/.test(request.pr) || !SHA.test(request.head) || !SHA.test(request.base)) {
    throw new Error("Invalid PR validation identity");
  }

  const repository = event.repository.full_name;
  const repo = context.repo;
  if (fresh && context.ref !== `refs/heads/${event.repository.default_branch}`) {
    throw new Error("Target refreshes must run from the default branch");
  }
  for (let attempt = 0; attempt < (fresh ? 12 : 1); attempt++) {
    const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: Number(request.pr) });
    const { data: ref } = await github.rest.git.getRef({ ...repo, ref: `heads/${pr.base.ref}` });
    const sameIdentity = pr.state === "open"
      && pr.base.repo.full_name === repository
      && pr.base.ref === request.target
      && pr.head.sha === request.head
      && ref.object.sha === request.base;
    if (!sameIdentity) throw new Error("PR source or target changed before validation could finish");
    if (fresh && !sameRepository(pr, repository)) {
      throw new Error("Fork PRs must run under GitHub's native workflow approval");
    }
    const merge = fresh ? pr.merge_commit_sha : context.sha;
    if (merge && pr.mergeable !== false) {
      const { data: commit } = await github.rest.git.getCommit({ ...repo, commit_sha: merge });
      if (commit.parents.length === 2
        && commit.parents[0].sha === request.base
        && commit.parents[1].sha === request.head) {
        const version = Boolean(managed(pr, repository, event.repository.default_branch));
        core.info(`PR #${request.pr} head=${request.head} base=${request.base} merge=${merge}`);
        for (const [key, value] of Object.entries({ merge, version, head: request.head, base: request.base })) {
          core.setOutput(key, value);
        }
        return merge;
      }
    }
    if (fresh && pr.mergeable !== false) await new Promise(resolve => setTimeout(resolve, 5000));
    else break;
  }
  throw new Error("GitHub did not provide a merge commit for the current PR source and target");
}

async function dispatchRefreshes(github, context, core) {
  const repository = context.payload.repository;
  const target = context.ref.slice("refs/heads/".length);
  const repo = context.repo;
  const prs = await github.paginate(github.rest.pulls.list, {
    ...repo, state: "open", base: target, per_page: 100,
  });
  for (const pr of prs) {
    if (!sameRepository(pr, repository.full_name)) {
      core.warning(`PR #${pr.number} requires a native pull_request run for the new target. Fork approval is not transferable.`);
      continue;
    }
    const { data: ref } = await github.rest.git.getRef({ ...repo, ref: `heads/${target}` });
    if (ref.object.sha !== context.sha) return;
    if (pr.merge_commit_sha && pr.base.sha === context.sha) {
      const checks = await github.paginate(github.rest.checks.listForRef, {
        ...repo, ref: pr.merge_commit_sha, check_name: "Validate integration", per_page: 100,
      });
      if (checks.some(check => check.app?.slug === "github-actions"
        && !["cancelled", "skipped", "stale"].includes(check.conclusion))) continue;
    }
    await github.rest.actions.createWorkflowDispatch({
      ...repo, workflow_id: "validate.yml", ref: repository.default_branch,
      inputs: { pr: String(pr.number), head: pr.head.sha, base: context.sha, target },
    });
  }
}

async function releasePR(github, context, core) {
  const event = context.payload;
  const number = String(event.pull_request?.number ?? event.inputs.pr);
  const source = event.pull_request?.merge_commit_sha ?? event.inputs.source;
  if (!/^[1-9][0-9]*$/.test(number) || !SHA.test(source)) {
    throw new Error("Expected the merged version PR number and full merge commit SHA");
  }
  const { data: pr } = await github.rest.pulls.get({ ...context.repo, pull_number: Number(number) });
  if (!pr.merged || pr.merge_commit_sha !== source
    || !managed(pr, event.repository.full_name, event.repository.default_branch)
    || !SHA.test(pr.head.sha)) {
    throw new Error("The source is not the merge of a managed version PR into the default branch");
  }
  core.setOutput("source", source);
  core.setOutput("head", pr.head.sha);
  core.setOutput("number", number);
}

module.exports = { resolvePR, dispatchRefreshes, releasePR };
