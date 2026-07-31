#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  EvidenceUnavailable,
  FULL_SHA,
  PolicyViolation,
  STABLE_SEMVER,
  UsageError,
  atomicWriteJson,
  canonicalJson,
  collectGithubChange,
  githubRequest,
  parseJsonStrict,
  readCanonicalJson,
  readRegularText,
  readRepositorySnapshot,
  safeErrorMessage,
  sha256Text,
  validateChange,
  validateConfiguration,
} from "./policy-lib.mjs";
import { verifyRunEvidence } from "./verify-run-evidence.mjs";
import { collectAndValidatePublication } from "./verify-trusted-publication.mjs";

const commands = new Set([
  "set-status",
  "validate-change",
  "validate-pipeline",
  "verify-run-evidence",
  "verify-trusted-publication",
  "write-promotion-receipt",
  "write-source-evidence",
]);

function parseArguments(argv) {
  const command = argv.shift();
  if (!commands.has(command)) throw new UsageError(`unknown or missing command: ${command ?? "(missing)"}`);
  const options = { github: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--github") {
      if (options.github) throw new UsageError("--github may be specified once");
      options.github = true;
      continue;
    }
    if (!argument.startsWith("--") || index + 1 >= argv.length) throw new UsageError(`invalid or incomplete argument: ${argument}`);
    const key = argument.slice(2).replace(/-([a-z])/gu, (_match, letter) => letter.toUpperCase());
    if (options[key] !== undefined) throw new UsageError(`${argument} may be specified once`);
    options[key] = argv[index + 1];
    index += 1;
  }
  return { command, options };
}

function requireOptions(options, names) {
  for (const name of names) if (!options[name]) throw new UsageError(`missing required option: --${name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)}`);
}

function positiveDecimal(value, label) {
  if (typeof value !== "string" || !/^[1-9]\d*$/u.test(value)) throw new UsageError(`${label} must be a positive decimal integer`);
  return value;
}

async function loadConfiguration(options) {
  const contractPath = path.resolve(options.contract ?? "pipeline.contract.json");
  const policyPath = path.resolve(options.policy ?? "channel-policy.json");
  const [{ text: contractText, value: contract }, { text: policyText, value: policy }] = await Promise.all([
    readCanonicalJson(contractPath),
    readCanonicalJson(policyPath),
  ]);
  validateConfiguration(contract, policy);
  return { contract, contractPath, contractSha256: sha256Text(contractText), policy, policyPath, policySha256: sha256Text(policyText) };
}

function checkWorkflowText(text, role, contract) {
  const forbidden = [
    /\bpaths-ignore\s*:/u,
    /\bpaths\s*:/u,
    /\bcontinue-on-error\s*:/u,
    /\bsecrets\s*\./u,
    /permissions\s*:\s*(?:read-all|write-all)/u,
    /github\.head_ref/u,
    /^\s*(?:npm|npx|pnpm|yarn|bun)\b/gmu,
    /^\s*eval\b/gmu,
  ];
  for (const pattern of forbidden) if (pattern.test(text)) throw new PolicyViolation(`${role} workflow contains forbidden construct: ${pattern}`);
  const uses = [...text.matchAll(/^\s*uses:\s*([^\s#]+)\s*$/gmu)].map((match) => match[1]);
  const allowedActions = new Set(Object.values(contract.toolchain.actions).map((action) => `${action.repository}@${action.commitSha}`));
  for (const action of uses) if (!allowedActions.has(action)) throw new PolicyViolation(`${role} workflow uses an unpinned or unknown action: ${action}`);
  if (uses.some((action) => !/@[0-9a-f]{40}$/u.test(action))) throw new PolicyViolation(`${role} workflow action is not full-SHA pinned`);
  const checkout = `${contract.toolchain.actions.checkout.repository}@${contract.toolchain.actions.checkout.commitSha}`;
  const checkoutCount = uses.filter((action) => action === checkout).length;
  const refs = [...text.matchAll(/^\s+ref:\s*(.+?)\s*$/gmu)].map((match) => match[1]);
  const credentialGuards = [...text.matchAll(/^\s+persist-credentials:\s*false\s*$/gmu)].length;
  if (checkoutCount === 0 || refs.length !== checkoutCount || credentialGuards !== checkoutCount) throw new PolicyViolation(`${role} workflow checkout must be explicit and credentialless`);
  const pullRequestBaseRef = "${{ github.event.pull_request.base.sha }}";
  const defaultBranchRef = "${{ github.event.repository.default_branch }}";
  const expectedRef = role === "manual-promotion" ? defaultBranchRef : pullRequestBaseRef;
  if (refs.some((ref) => ref !== expectedRef)) throw new PolicyViolation(`${role} workflow may check out only its trusted policy ref`);
  const conditions = [...text.matchAll(/^\s+if:\s*(.+?)\s*$/gmu)].map((match) => match[1]);
  if (role === "trusted-policy") {
    if (conditions.length !== 1 || conditions[0] !== "${{ always() }}") throw new PolicyViolation("trusted workflow may use only the final fail-closed condition");
  } else if (conditions.length !== 0) {
    throw new PolicyViolation(`${role} workflow must not contain conditional jobs or steps`);
  }
  if (role === "source-ci") {
    for (const token of ["pull_request:", "channel-data:", "name: channel-data", "validate-change", "--github", "write-source-evidence", "contents: read"]) if (!text.includes(token)) throw new PolicyViolation(`source workflow is missing ${token}`);
    if (text.includes("pull_request_target:") || text.includes("statuses: write")) throw new PolicyViolation("source workflow trust boundary is invalid");
  }
  if (role === "trusted-policy") {
    for (const token of ["pull_request_target:", "initialize-trusted-status:", "validate-candidate-data:", "publish-trusted-status:", "verify-trusted-publication", "--state pending", "--context trusted-policy", "statuses: write"]) if (!text.includes(token)) throw new PolicyViolation(`trusted workflow is missing ${token}`);
    if (text.includes("upload-artifact@") || text.includes("workflow_dispatch:")) throw new PolicyViolation("trusted workflow must not publish artifacts or accept manual dispatch");
    if ((text.match(/verify-trusted-publication/gu) ?? []).length !== 2 || (text.match(/set-status/gu) ?? []).length !== 2) throw new PolicyViolation("trusted workflow must bind both status transitions exactly once");
  }
  if (role === "manual-promotion") {
    for (const token of ["workflow_dispatch:", "verify-promotion:", "verify-run-evidence", "write-promotion-receipt", "actions: read", "contents: read"]) if (!text.includes(token)) throw new PolicyViolation(`promotion workflow is missing ${token}`);
    if (text.includes("set-status") || text.includes("pull_request_target:")) throw new PolicyViolation("promotion workflow must remain read-only");
  }
}

async function validatePipeline(options) {
  const configuration = await loadConfiguration(options);
  const root = path.resolve(options.root ?? ".");
  const rootMetadata = await import("node:fs/promises").then(({ lstat }) => lstat(root).catch(() => null));
  if (!rootMetadata?.isDirectory() || rootMetadata.isSymbolicLink()) throw new UsageError("--root must be a real directory");
  const workflows = {
    "manual-promotion": configuration.contract.trustZones["manual-promotion"].workflowPath,
    "source-ci": configuration.contract.trustZones["source-ci"].workflowPath,
    "trusted-policy": configuration.contract.trustZones["trusted-policy"].workflowPath,
  };
  for (const [role, relativePath] of Object.entries(workflows)) {
    const text = await readRegularText(path.join(root, relativePath), 256 * 1024);
    checkWorkflowText(text, role, configuration.contract);
  }
  return {
    approvedExceptions: [configuration.policy.providerException.exceptionId],
    contractSha256: configuration.contractSha256,
    externalHolds: configuration.contract.externalHolds,
    policySha256: configuration.policySha256,
    status: "PASS",
    validatedWorkflows: Object.keys(workflows).sort(),
  };
}

function gitHead(root) {
  const result = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "rev-parse", "HEAD"], { cwd: root, encoding: "utf8", timeout: 10000 });
  const sha = result.status === 0 ? result.stdout.trim() : "";
  if (!FULL_SHA.test(sha)) throw new EvidenceUnavailable("offline base Git commit is unavailable; pass --base-sha");
  return sha;
}

async function validateChangeCommand(options) {
  requireOptions(options, ["output"]);
  const configuration = await loadConfiguration(options);
  let result;
  let baseSha = options.baseSha;
  let repository = configuration.contract.canonical.repository.fullName;
  let headSha = options.headSha ?? null;
  if (options.github) {
    requireOptions(options, ["repository", "prNumber", "baseSha", "headSha"]);
    positiveDecimal(options.prNumber, "--pr-number");
    if (!FULL_SHA.test(options.baseSha) || !FULL_SHA.test(options.headSha)) throw new UsageError("base/head must be full SHAs");
    repository = options.repository;
    result = await collectGithubChange({ repository, prNumber: options.prNumber, baseSha: options.baseSha, headSha: options.headSha, contract: configuration.contract, policy: configuration.policy });
  } else {
    requireOptions(options, ["baseRoot", "candidateRoot"]);
    baseSha = baseSha ?? gitHead(path.resolve(options.baseRoot));
    if (!FULL_SHA.test(baseSha)) throw new UsageError("--base-sha must be a full SHA");
    const [base, candidate] = await Promise.all([
      readRepositorySnapshot(options.baseRoot, configuration.policy),
      readRepositorySnapshot(options.candidateRoot, configuration.policy),
    ]);
    result = await validateChange({ base, candidate, baseSha, contract: configuration.contract, policy: configuration.policy });
  }
  const receipt = {
    approvedExceptions: [configuration.policy.providerException.exceptionId],
    baseSha,
    changedPaths: result.changedPaths,
    classification: result.classification,
    contractSha256: configuration.contractSha256,
    externalHolds: result.classification === "stable-channel" ? [] : configuration.contract.externalHolds,
    headSha,
    policySha256: configuration.policySha256,
    repository,
    schema: "netlist-studio.channel-validation",
    schemaVersion: 1,
  };
  await atomicWriteJson(path.resolve(options.output), receipt);
  return receipt;
}

async function verifyTrustedPublication(options) {
  if (!options.github) throw new UsageError("verify-trusted-publication requires --github");
  requireOptions(options, ["repository", "workflowPath", "prNumber", "baseSha", "headSha", "runId", "attempt"]);
  return collectAndValidatePublication(options);
}

async function setStatus(options) {
  if (!options.github) throw new UsageError("set-status requires --github");
  requireOptions(options, ["repository", "sha", "state", "context", "description", "targetUrl"]);
  if (!FULL_SHA.test(options.sha) || !["pending", "success", "failure"].includes(options.state) || options.context !== "trusted-policy" || options.description.length > 140 || !/^https:\/\//u.test(options.targetUrl)) throw new UsageError("status arguments are invalid");
  const repository = options.repository.split("/").map(encodeURIComponent).join("/");
  const response = await githubRequest(`/repos/${repository}/statuses/${options.sha}`, { method: "POST", body: { context: options.context, description: options.description, state: options.state, target_url: options.targetUrl } });
  return { context: response.context, creatorId: response.creator?.id ?? null, sha: response.sha, state: response.state, targetUrl: response.target_url };
}

async function writeSourceEvidence(options) {
  requireOptions(options, ["output", "contract", "policy", "repository", "workflowPath", "baseSha", "headSha", "runId", "attempt", "validationResult"]);
  const configuration = await loadConfiguration(options);
  if (!FULL_SHA.test(options.baseSha) || !FULL_SHA.test(options.headSha)) throw new UsageError("base/head must be full SHAs");
  positiveDecimal(options.runId, "--run-id");
  positiveDecimal(options.attempt, "--attempt");
  const validationText = await readRegularText(path.resolve(options.validationResult));
  const validation = parseJsonStrict(validationText);
  if (validationText !== canonicalJson(validation) || validation.schema !== "netlist-studio.channel-validation" || validation.repository !== options.repository || validation.baseSha !== options.baseSha || validation.headSha !== options.headSha || validation.contractSha256 !== configuration.contractSha256 || validation.policySha256 !== configuration.policySha256) throw new PolicyViolation("validation result binding is invalid");
  const receipt = {
    attempt: options.attempt,
    baseSha: options.baseSha,
    classification: validation.classification,
    contractSha256: configuration.contractSha256,
    event: "pull_request",
    headSha: options.headSha,
    policySha256: configuration.policySha256,
    repository: options.repository,
    runId: options.runId,
    schema: "netlist-studio.channel-source-evidence",
    schemaVersion: 1,
    workflowPath: options.workflowPath,
  };
  await atomicWriteJson(path.resolve(options.output), receipt);
  return receipt;
}

async function verifyRun(options) {
  if (!options.github) throw new UsageError("verify-run-evidence requires --github");
  requireOptions(options, ["output", "contract", "policy", "binding", "runId", "attempt", "baseSha", "headSha", "version"]);
  const configuration = await loadConfiguration(options);
  const receipt = await verifyRunEvidence({ attempt: options.attempt, baseSha: options.baseSha, binding: options.binding, contract: configuration.contract, headSha: options.headSha, runId: options.runId, version: options.version });
  await atomicWriteJson(path.resolve(options.output), receipt);
  return receipt;
}

async function writePromotionReceipt(options) {
  requireOptions(options, ["output", "contract", "policy", "version", "baseSha", "headSha", "sourceRunReceipt", "trustedRunReceipt"]);
  if (!STABLE_SEMVER.test(options.version) || !FULL_SHA.test(options.baseSha) || !FULL_SHA.test(options.headSha)) throw new UsageError("promotion version/base/head is invalid");
  const configuration = await loadConfiguration(options);
  const [sourceText, trustedText] = await Promise.all([readRegularText(path.resolve(options.sourceRunReceipt)), readRegularText(path.resolve(options.trustedRunReceipt))]);
  const source = parseJsonStrict(sourceText);
  const trusted = parseJsonStrict(trustedText);
  if (sourceText !== canonicalJson(source) || trustedText !== canonicalJson(trusted) || source.binding !== "source-ci" || trusted.binding !== "trusted-policy") throw new PolicyViolation("run receipts are not canonical source/trusted evidence");
  for (const receipt of [source, trusted]) if (receipt.version !== options.version || receipt.baseSha !== options.baseSha || receipt.headSha !== options.headSha || receipt.repository !== configuration.contract.canonical.repository.fullName || receipt.conclusion !== "success") throw new PolicyViolation("run receipt request binding drifted");
  const promotion = {
    authorization: "none",
    baseSha: options.baseSha,
    contractSha256: configuration.contractSha256,
    externalMutationHandoff: "none",
    grantsExternalMutationAuthority: false,
    headSha: options.headSha,
    policySha256: configuration.policySha256,
    repository: configuration.contract.canonical.repository.fullName,
    schema: "netlist-studio.channel-promotion-evidence",
    schemaVersion: 1,
    sourceRun: source,
    trustedRun: trusted,
    version: options.version,
  };
  await atomicWriteJson(path.resolve(options.output), promotion);
  return promotion;
}

export async function run(argv) {
  const { command, options } = parseArguments([...argv]);
  if (command === "validate-pipeline") return validatePipeline(options);
  if (command === "validate-change") return validateChangeCommand(options);
  if (command === "verify-trusted-publication") return verifyTrustedPublication(options);
  if (command === "set-status") return setStatus(options);
  if (command === "write-source-evidence") return writeSourceEvidence(options);
  if (command === "verify-run-evidence") return verifyRun(options);
  return writePromotionReceipt(options);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const result = await run(process.argv.slice(2));
    process.stdout.write(canonicalJson(result));
  } catch (error) {
    process.stderr.write(`${safeErrorMessage(error)}\n`);
    process.exitCode = error?.exitCode ?? 2;
  }
}
