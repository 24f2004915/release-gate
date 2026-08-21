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

function hasExactKeys(obj, keys) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return false;
  }

  const actual = Object.keys(obj).sort();
  const expected = [...keys].sort();

  return JSON.stringify(actual) === JSON.stringify(expected);
}

function isString(value) {
  return typeof value === "string";
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isValidTopLevelPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return false;
  }

  const allowedKeys = [
    "provenance",
    "humanApproved",
    "untrustedContent",
    "action"
  ];

  for (const key of Object.keys(payload)) {
    if (!allowedKeys.includes(key)) {
      return false;
    }
  }

  if (!(payload.provenance === "trusted" || payload.provenance === "untrusted")) {
    return false;
  }

  if (typeof payload.humanApproved !== "boolean") {
    return false;
  }

  if (
    "untrustedContent" in payload &&
    typeof payload.untrustedContent !== "string"
  ) {
    return false;
  }

  if (
    !payload.action ||
    typeof payload.action !== "object" ||
    Array.isArray(payload.action)
  ) {
    return false;
  }

  if (!hasExactKeys(payload.action, ["tool", "args"])) {
    return false;
  }

  if (typeof payload.action.tool !== "string") {
    return false;
  }

  if (
    !payload.action.args ||
    typeof payload.action.args !== "object" ||
    Array.isArray(payload.action.args)
  ) {
    return false;
  }

  return true;
}

function isUnsafeHtml(html) {
  const lower = html.toLowerCase();

  if (/<\s*script\b/i.test(html)) {
    return true;
  }

  if (/<\s*iframe\b/i.test(html)) {
    return true;
  }

  if (/\son[a-z]+\s*=/i.test(html)) {
    return true;
  }

  if (/javascript\s*:/i.test(lower)) {
    return true;
  }

  return false;
}

export function evaluateActionFirewall(payload) {
  if (!isValidTopLevelPayload(payload)) {
    return {
      decision: "block",
      reason: "INVALID_SCHEMA"
    };
  }

  const { humanApproved, action } = payload;
  const { tool, args } = action;

  const allowedTools = ["search", "lookup_record", "send_email", "render_html"];

  if (!allowedTools.includes(tool)) {
    return {
      decision: "block",
      reason: "TOOL_NOT_ALLOWED"
    };
  }

  if (tool === "search") {
    if (!hasExactKeys(args, ["query"])) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (!isString(args.query) || args.query.length < 1 || args.query.length > 200) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }
  }

  if (tool === "lookup_record") {
    if (!hasExactKeys(args, ["tenantId", "recordId"])) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (!isString(args.tenantId) || !isNonEmptyString(args.recordId)) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (args.tenantId !== "tenant-60b8cdd") {
      return {
        decision: "block",
        reason: "TENANT_SCOPE"
      };
    }
  }

  if (tool === "send_email") {
    if (!hasExactKeys(args, ["to", "subject", "body"])) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (!isString(args.to) || !isString(args.subject) || !isString(args.body)) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    const parts = args.to.split("@");

    if (
      parts.length !== 2 ||
      parts[0].length === 0 ||
      parts[1] !== "notify-lqm4v0r.example"
    ) {
      return {
        decision: "block",
        reason: "EGRESS_DENIED"
      };
    }

    if (humanApproved !== true) {
      return {
        decision: "block",
        reason: "APPROVAL_REQUIRED"
      };
    }
  }

  if (tool === "render_html") {
    if (!hasExactKeys(args, ["html"])) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (!isString(args.html)) {
      return {
        decision: "block",
        reason: "INVALID_SCHEMA"
      };
    }

    if (isUnsafeHtml(args.html)) {
      return {
        decision: "block",
        reason: "UNSAFE_OUTPUT"
      };
    }
  }

  return {
    decision: "allow",
    reason: "ALLOW"
  };
}

app.post("/action-firewall", (req, res) => {
  res.json(evaluateActionFirewall(req.body));
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOnlyKeys(obj, keys) {
  if (!isPlainObject(obj)) {
    return false;
  }

  const actual = Object.keys(obj).sort();
  const expected = [...keys].sort();

  return JSON.stringify(actual) === JSON.stringify(expected);
}

function isValidTerraformPlanShape(payload) {
  if (!hasOnlyKeys(payload, [
    "environment",
    "state",
    "providerVersion",
    "destroyApproved",
    "resource"
  ])) {
    return false;
  }

  if (typeof payload.environment !== "string") {
    return false;
  }

  if (!hasOnlyKeys(payload.state, ["backend", "locked"])) {
    return false;
  }

  if (typeof payload.state.backend !== "string") {
    return false;
  }

  if (typeof payload.state.locked !== "boolean") {
    return false;
  }

  if (typeof payload.providerVersion !== "string") {
    return false;
  }

  if (typeof payload.destroyApproved !== "boolean") {
    return false;
  }

  const resource = payload.resource;

  if (!hasOnlyKeys(resource, [
    "address",
    "type",
    "action",
    "labels",
    "secret",
    "forceDestroy"
  ])) {
    return false;
  }

  if (typeof resource.address !== "string") {
    return false;
  }

  if (typeof resource.type !== "string") {
    return false;
  }

  if (!["create", "update", "delete"].includes(resource.action)) {
    return false;
  }

  if (!isPlainObject(resource.labels)) {
    return false;
  }

  for (const [key, value] of Object.entries(resource.labels)) {
    if (typeof key !== "string" || typeof value !== "string") {
      return false;
    }
  }

  if (
    resource.secret !== null &&
    typeof resource.secret !== "string"
  ) {
    return false;
  }

  if (typeof resource.forceDestroy !== "boolean") {
    return false;
  }

  return true;
}

export function evaluateTerraformPlan(payload) {
  // 1. Schema and value types
  if (!isValidTerraformPlanShape(payload)) {
    return {
      decision: "reject",
      reason: "INVALID_PLAN"
    };
  }

  const { environment, state, providerVersion, destroyApproved, resource } = payload;

  // 2. Environment
  if (environment !== "prod-mxingx") {
    return {
      decision: "reject",
      reason: "ENVIRONMENT_MISMATCH"
    };
  }

  // 3. Remote state and locking
  const allowedBackends = ["gcs", "s3", "azurerm", "remote"];

  if (!allowedBackends.includes(state.backend) || state.locked !== true) {
    return {
      decision: "reject",
      reason: "STATE_UNSAFE"
    };
  }

  // 4. Provider pinning
  const exactVersionRegex = /^(= )?6\.2\.1$/;
  const pessimisticVersionRegex = /^~> 6\.0$/;

  if (
    !exactVersionRegex.test(providerVersion) &&
    !pessimisticVersionRegex.test(providerVersion)
  ) {
    return {
      decision: "reject",
      reason: "UNPINNED_PROVIDER"
    };
  }

  // 5. Required labels
  const requiredLabels = {
    owner: "student-mr4a3",
    environment: "production",
    cost_center: "cc-eq4q"
  };

  for (const [key, value] of Object.entries(requiredLabels)) {
    if (resource.labels[key] !== value) {
      return {
        decision: "reject",
        reason: "MISSING_LABELS"
      };
    }
  }

  // 6. Secret must be null or secret:// reference
  if (
    resource.secret !== null &&
    !/^secret:\/\/.+/.test(resource.secret)
  ) {
    return {
      decision: "reject",
      reason: "PLAINTEXT_SECRET"
    };
  }

  // 7. Stateful delete approval
  const statefulTypes = [
    "storage_bucket",
    "sql_database",
    "persistent_disk"
  ];

  if (
    resource.action === "delete" &&
    statefulTypes.includes(resource.type) &&
    destroyApproved !== true
  ) {
    return {
      decision: "reject",
      reason: "DELETE_NOT_APPROVED"
    };
  }

  // 8. Production storage bucket forceDestroy
  if (
    resource.type === "storage_bucket" &&
    resource.forceDestroy === true
  ) {
    return {
      decision: "reject",
      reason: "FORCE_DESTROY"
    };
  }

  return {
    decision: "approve",
    reason: "APPROVE"
  };
}

app.post("/terraform/plan", (req, res) => {
  res.json(evaluateTerraformPlan(req.body));
});

export default app;
