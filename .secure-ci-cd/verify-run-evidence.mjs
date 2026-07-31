import {
  EvidenceUnavailable,
  FULL_SHA,
  PolicyViolation,
  STABLE_SEMVER,
  githubRequest,
} from "./policy-lib.mjs";

function decimal(value, label) {
  const result = typeof value === "number" ? String(value) : value;
  if (typeof result !== "string" || !/^[1-9]\d*$/u.test(result)) throw new EvidenceUnavailable(`${label} must be positive`);
  return result;
}

function pullBindings(run) {
  return Array.isArray(run?.pull_requests) ? run.pull_requests.map((pull) => ({ baseSha: pull?.base?.sha, headSha: pull?.head?.sha })) : [];
}

function matches(run, event, baseSha, headSha) {
  return run.event === event && pullBindings(run).some((pull) => pull.baseSha === baseSha && pull.headSha === headSha);
}

async function pages(endpoint, key) {
  const result = [];
  for (let page = 1; page <= 10; page += 1) {
    const payload = await githubRequest(`${endpoint}${endpoint.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    if (!Array.isArray(payload?.[key])) throw new EvidenceUnavailable(`GitHub response is missing ${key}`);
    result.push(...payload[key]);
    if (payload[key].length < 100) return result;
  }
  throw new EvidenceUnavailable("GitHub evidence inventory exceeds 1000 entries");
}

export async function verifyRunEvidence({ attempt, baseSha, binding, contract, headSha, runId, version }) {
  const normalizedRunId = decimal(runId, "run ID");
  const normalizedAttempt = decimal(attempt, "attempt");
  if (!FULL_SHA.test(baseSha) || !FULL_SHA.test(headSha) || !STABLE_SEMVER.test(version)) throw new EvidenceUnavailable("run binding arguments are invalid");
  const zone = contract.trustZones?.[binding];
  if (!zone || !["source-ci", "trusted-policy"].includes(binding)) throw new EvidenceUnavailable("unknown evidence binding");
  const repository = contract.canonical.repository.fullName;
  const encoded = repository.split("/").map(encodeURIComponent).join("/");
  const run = await githubRequest(`/repos/${encoded}/actions/runs/${normalizedRunId}`);
  const workflow = await githubRequest(`/repos/${encoded}/actions/workflows/${encodeURIComponent(run.workflow_id)}`);
  if (workflow.path !== zone.workflowPath || !matches(run, zone.event, baseSha, headSha) || String(run.run_attempt) !== normalizedAttempt) throw new PolicyViolation("workflow run binding changed");
  const allRuns = await pages(`/repos/${encoded}/actions/workflows/${encodeURIComponent(run.workflow_id)}/runs?event=${encodeURIComponent(zone.event)}`, "workflow_runs");
  const matching = allRuns.filter((candidate) => matches(candidate, zone.event, baseSha, headSha)).sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)) || Number(right.id) - Number(left.id));
  if (String(matching[0]?.id) !== normalizedRunId) throw new PolicyViolation("workflow run was superseded");
  if (run.status !== "completed") throw new EvidenceUnavailable("workflow run is not completed");
  if (run.conclusion !== "success") throw new PolicyViolation(`workflow run did not succeed: ${run.conclusion}`);
  const jobs = await pages(`/repos/${encoded}/actions/runs/${normalizedRunId}/attempts/${normalizedAttempt}/jobs`, "jobs");
  const expectedJobs = binding === "source-ci" ? ["channel-data"] : ["initialize-trusted-status", "validate-candidate-data", "publish-trusted-status"];
  const selectedJobs = expectedJobs.map((name) => {
    const candidates = jobs.filter((job) => job.name === name);
    if (candidates.length !== 1 || candidates[0].status !== "completed" || candidates[0].conclusion !== "success") throw new PolicyViolation(`required job is not uniquely successful: ${name}`);
    return { conclusion: "success", id: String(candidates[0].id), name };
  });
  const artifacts = await pages(`/repos/${encoded}/actions/runs/${normalizedRunId}/artifacts`, "artifacts");
  let selectedArtifacts = [];
  if (binding === "source-ci") {
    const expectedName = contract.promotion.evidenceArtifactName.replace("{runId}", normalizedRunId).replace("{attempt}", normalizedAttempt).replace("{headSha}", headSha);
    const candidates = artifacts.filter((artifact) => artifact.name === expectedName && artifact.expired !== true);
    if (candidates.length !== 1 || typeof candidates[0].digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(candidates[0].digest) || !Number.isSafeInteger(candidates[0].size_in_bytes)) throw new EvidenceUnavailable("source evidence artifact binding is unavailable");
    selectedArtifacts = [{ id: String(candidates[0].id), name: expectedName, sha256: candidates[0].digest.slice(7), size: candidates[0].size_in_bytes }];
  } else if (artifacts.length !== 0) {
    throw new PolicyViolation("trusted policy run must not publish artifacts");
  }
  return Object.freeze({
    attempt: normalizedAttempt,
    baseSha,
    binding,
    conclusion: "success",
    event: zone.event,
    headSha,
    jobs: selectedJobs,
    artifacts: selectedArtifacts,
    repository,
    runId: normalizedRunId,
    version,
    workflowPath: zone.workflowPath,
  });
}
