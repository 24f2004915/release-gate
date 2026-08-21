import express from "express";

export function evaluateReleaseGate(payload) {
  const violations = [];

  const workflow = payload?.workflow ?? {};
  const image = payload?.image ?? {};
  const permissions = workflow?.permissions ?? {};

  const permissionKeys = Object.keys(permissions).sort();
  const requiredKeys = ["contents", "id-token", "packages"].sort();

  const exactPermissionKeys =
    JSON.stringify(permissionKeys) === JSON.stringify(requiredKeys);

  const exactPermissionValues =
    permissions.contents === "read" &&
    permissions.packages === "write" &&
    permissions["id-token"] === "none";

  if (!exactPermissionKeys || !exactPermissionValues) {
    violations.push("EXCESS_PERMISSION");
  }

  if (payload?.event === "pull_request" && workflow.trigger !== "pull_request") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  if (workflow.trigger === "pull_request_target") {
    if (!violations.includes("UNSAFE_PR_TRIGGER")) {
      violations.push("UNSAFE_PR_TRIGGER");
    }
  }

  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }

  const fullShaRegex = /^[0-9a-f]{40}$/;

  for (const action of workflow.actions ?? []) {
    if (action?.owner !== "actions" && !fullShaRegex.test(action?.ref ?? "")) {
      violations.push("MUTABLE_ACTION");
      break;
    }
  }

  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  if (!(image.secretMode === "none" || image.secretMode === "buildkit")) {
    violations.push("SECRET_IN_LAYER");
  }

  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  if (payload?.target === "production") {
    if (payload?.event !== "push" || payload?.ref !== "refs/heads/main") {
      violations.push("INVALID_PRODUCTION_REF");
    }

    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations
  };
}

const app = express();

app.use(express.json());

app.post("/release-gate", (req, res) => {
  res.json(evaluateReleaseGate(req.body));
});

export default app;
