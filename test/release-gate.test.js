import test from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import app, { evaluateReleaseGate } from "../src/app.js";

const safePreviewPayload = {
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/feature-x",
  workflow: {
    trigger: "pull_request",
    permissions: {
      contents: "read",
      packages: "write",
      "id-token": "none"
    },
    testsPassed: true,
    matrixComplete: true,
    failFast: false,
    actions: [
      {
        owner: "actions",
        name: "checkout",
        ref: "v4"
      },
      {
        owner: "docker",
        name: "login-action",
        ref: "0123456789abcdef0123456789abcdef01234567"
      }
    ]
  },
  image: {
    multiStage: true,
    runsAsRoot: false,
    secretMode: "buildkit",
    criticalVulnerabilities: 0,
    digestPinned: true
  }
};

const safeProductionPayload = {
  ...safePreviewPayload,
  target: "production",
  event: "push",
  ref: "refs/heads/main",
  workflow: {
    ...safePreviewPayload.workflow,
    trigger: "push",
    environmentApproval: true
  }
};

test("safe preview promotes", () => {
  assert.deepEqual(evaluateReleaseGate(safePreviewPayload), {
    decision: "promote",
    violations: []
  });
});

test("safe production promotes", () => {
  assert.deepEqual(evaluateReleaseGate(safeProductionPayload), {
    decision: "promote",
    violations: []
  });
});

test("multi-failure payload blocks with expected violations", () => {
  const badPayload = {
    target: "production",
    event: "pull_request",
    ref: "refs/heads/dev",
    workflow: {
      trigger: "pull_request_target",
      permissions: {
        contents: "write",
        packages: "write",
        "id-token": "write",
        issues: "write"
      },
      testsPassed: false,
      matrixComplete: false,
      failFast: true,
      actions: [
        {
          owner: "somebody",
          name: "unsafe-action",
          ref: "v1"
        }
      ],
      environmentApproval: false
    },
    image: {
      multiStage: false,
      runsAsRoot: true,
      secretMode: "copy",
      criticalVulnerabilities: 3,
      digestPinned: false
    }
  };

  const result = evaluateReleaseGate(badPayload);

  assert.equal(result.decision, "block");

  for (const code of [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED"
  ]) {
    assert.ok(result.violations.includes(code), `${code} missing`);
  }
});

test("POST /release-gate returns JSON decision", async () => {
  const response = await request(app)
    .post("/release-gate")
    .send(safePreviewPayload)
    .expect(200);

  assert.deepEqual(response.body, {
    decision: "promote",
    violations: []
  });
});
