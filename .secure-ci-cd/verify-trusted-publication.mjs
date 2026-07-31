import {
  EvidenceUnavailable,
  FULL_SHA,
  PolicyViolation,
  githubRequest,
} from "./policy-lib.mjs";

function decimal(value, label) {
  const normalized = typeof value === "number" ? String(value) : value;
  if ((typeof value === "number" && !Number.isSafeInteger(value)) || typeof normalized !== "string" || !/^[1-9]\d*$/u.test(normalized)) {
    throw new EvidenceUnavailable(`${label} must be a positive decimal integer`);
  }
  return normalized;
}

function normalizeRun(run) {
  return {
    attempt: decimal(run?.run_attempt, "workflow run attempt"),
    createdAt: run?.created_at,
    event: run?.event,
    id: decimal(run?.id, "workflow run id"),
    pulls: Array.isArray(run?.pull_requests)
      ? run.pull_requests.map((pull) => ({ baseSha: pull?.base?.sha, headSha: pull?.head?.sha, number: decimal(pull?.number, "pull request number") }))
      : [],
    workflowId: decimal(run?.workflow_id, "workflow id"),
  };
}

function sameBinding(run, args) {
  return run.event === "pull_request_target" && run.pulls.some((pull) => pull.number === args.prNumber && pull.baseSha === args.baseSha && pull.headSha === args.headSha);
}

function newest(runs) {
  return [...runs].sort((left, right) => String(right.createdAt).localeCompare(String(left.createdAt)) || (BigInt(right.id) > BigInt(left.id) ? 1 : -1))[0];
}

function validateStatusInput(input) {
  if (!FULL_SHA.test(input.headSha ?? "") || !["pending", "success", "failure"].includes(input.state) || input.context !== "trusted-policy" || typeof input.description !== "string" || input.description.length === 0 || input.description.length > 140 || typeof input.targetUrl !== "string" || !/^https:\/\/github\.com\//u.test(input.targetUrl)) {
    throw new EvidenceUnavailable("trusted status arguments are invalid");
  }
  return input;
}

export function validateStatusResponse(response, input) {
  if (response?.sha !== input.headSha || response?.context !== input.context || response?.state !== input.state || response?.target_url !== input.targetUrl) {
    throw new PolicyViolation("GitHub status response binding changed");
  }
  return Object.freeze({ context: response.context, creatorId: response.creator?.id ?? null, sha: response.sha, state: response.state, targetUrl: response.target_url });
}

export function validatePublicationSnapshot(snapshot, input) {
  const args = {
    ...input,
    attempt: decimal(input.attempt, "attempt"),
    prNumber: decimal(input.prNumber, "PR number"),
    runId: decimal(input.runId, "run ID"),
  };
  if (!FULL_SHA.test(args.baseSha) || !FULL_SHA.test(args.headSha)) throw new EvidenceUnavailable("base/head must be full SHAs");
  if (snapshot?.repository?.fullName !== args.repository || snapshot?.pr?.state !== "open" || decimal(snapshot?.pr?.number, "current PR number") !== args.prNumber || snapshot?.pr?.baseSha !== args.baseSha || snapshot?.pr?.headSha !== args.headSha || snapshot?.pr?.headRepository !== args.repository) {
    throw new PolicyViolation("current pull request binding changed");
  }
  if (snapshot?.workflow?.path !== args.workflowPath || decimal(snapshot?.workflow?.id, "workflow id") !== decimal(snapshot?.run?.workflowId, "run workflow id")) throw new PolicyViolation("trusted workflow identity changed");
  const current = { ...snapshot.run, id: decimal(snapshot.run.id, "current run id"), attempt: decimal(snapshot.run.attempt, "current run attempt"), workflowId: decimal(snapshot.run.workflowId, "current workflow id") };
  if (current.id !== args.runId || current.attempt !== args.attempt || !sameBinding(current, args)) throw new PolicyViolation("current trusted run binding changed");
  if (!Array.isArray(snapshot.workflowRuns)) throw new EvidenceUnavailable("workflow run inventory is unavailable");
  const matching = snapshot.workflowRuns.filter((run) => sameBinding(run, args));
  if (matching.length === 0) throw new EvidenceUnavailable("matching trusted run is unavailable");
  if (newest(matching).id !== args.runId) throw new PolicyViolation("trusted run was superseded");
  return Object.freeze({ attempt: args.attempt, baseSha: args.baseSha, headSha: args.headSha, prNumber: args.prNumber, repository: args.repository, runId: args.runId, status: "PASS", workflowPath: args.workflowPath });
}

async function collectPages(endpoint, key, request = githubRequest) {
  const values = [];
  for (let page = 1; page <= 10; page += 1) {
    const payload = await request(`${endpoint}${endpoint.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    if (!Array.isArray(payload?.[key])) throw new EvidenceUnavailable(`GitHub response is missing ${key}`);
    values.push(...payload[key]);
    if (payload[key].length < 100) return values;
  }
  throw new EvidenceUnavailable("GitHub run inventory exceeds 1000 entries");
}

export async function collectAndValidatePublication(input, request = githubRequest) {
  const repositoryPath = input.repository.split("/").map(encodeURIComponent).join("/");
  const [repository, pr, rawRun] = await Promise.all([
    request(`/repos/${repositoryPath}`),
    request(`/repos/${repositoryPath}/pulls/${encodeURIComponent(input.prNumber)}`),
    request(`/repos/${repositoryPath}/actions/runs/${encodeURIComponent(input.runId)}`),
  ]);
  const workflow = await request(`/repos/${repositoryPath}/actions/workflows/${encodeURIComponent(rawRun.workflow_id)}`);
  const workflowRuns = await collectPages(`/repos/${repositoryPath}/actions/workflows/${encodeURIComponent(rawRun.workflow_id)}/runs?event=pull_request_target`, "workflow_runs", request);
  return validatePublicationSnapshot({
    pr: { baseSha: pr.base?.sha, headRepository: pr.head?.repo?.full_name, headSha: pr.head?.sha, number: String(pr.number), state: pr.state },
    repository: { fullName: repository.full_name },
    run: normalizeRun(rawRun),
    workflow: { id: String(workflow.id), path: workflow.path },
    workflowRuns: workflowRuns.map(normalizeRun),
  }, input);
}

export async function createTrustedStatus(input, request = githubRequest) {
  validateStatusInput(input);
  const repositoryPath = input.repository.split("/").map(encodeURIComponent).join("/");
  return request(`/repos/${repositoryPath}/statuses/${input.headSha}`, {
    method: "POST",
    body: {
      context: input.context,
      description: input.description,
      state: input.state,
      target_url: input.targetUrl,
    },
  });
}

export async function publishTrustedStatus(input, dependencies = {}) {
  validateStatusInput(input);
  const collect = dependencies.collect ?? collectAndValidatePublication;
  const createStatus = dependencies.createStatus ?? createTrustedStatus;
  await collect(input);
  try {
    const response = await createStatus(input);
    const status = validateStatusResponse(response, input);
    await collect(input);
    return Object.freeze({ ...status, publication: "PASS" });
  } catch (error) {
    if (input.state === "success") {
      const failure = {
        ...input,
        description: "trusted publication became stale",
        state: "failure",
      };
      try {
        validateStatusResponse(await createStatus(failure), failure);
      } catch {
        throw new EvidenceUnavailable("stale trusted success could not be invalidated");
      }
    }
    throw error;
  }
}
