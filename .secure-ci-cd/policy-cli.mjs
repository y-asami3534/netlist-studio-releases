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
  parseJsonStrict,
  readCanonicalJson,
  readRegularText,
  readRepositorySnapshot,
  safeErrorMessage,
  sha256Text,
  validateChange,
  validateConfiguration,
  validateWorkflowText,
} from "./policy-lib.mjs";
import { verifyRunEvidence } from "./verify-run-evidence.mjs";
import { publishTrustedStatus } from "./verify-trusted-publication.mjs";

const commands = new Set([
  "publish-trusted-status",
  "validate-change",
  "validate-pipeline",
  "verify-run-evidence",
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
    validateWorkflowText(text, role, configuration.contract);
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

async function publishStatus(options) {
  if (!options.github) throw new UsageError("publish-trusted-status requires --github");
  requireOptions(options, ["repository", "workflowPath", "prNumber", "baseSha", "headSha", "runId", "attempt", "state", "context", "description", "targetUrl"]);
  return publishTrustedStatus(options);
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
  if (command === "publish-trusted-status") return publishStatus(options);
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
