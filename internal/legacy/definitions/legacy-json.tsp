model SemVerInfo {
  vulnerable: string[];
  vulnerableHashes?: string[];
  hashRange?: string[];
}

enum VulnerabilityType {
  license,
  other,
}

enum VulnerabilitySeverity {
  none,
  low,
  medium,
  high,
  critical,
}

enum Reachability {
  reachable,
  `no-path-found`,
  `not-applicable`,
}

model ReachableFunctionPaths {
  functionName: string;
  callPaths: string[][];
}

model ReachablePaths {
  pathCount: uint32;
  paths: ReachableFunctionPaths[];
}

alias UpgradePath = string | boolean;

model FunctionId {
  className: string | null;
  ...NewFunctionId;
}

model NewFunctionId {
  filePath: string;
  functionName: string;
}

model FunctionInfo {
  functionId: FunctionId;
  version: string[];
}

model NewFunctionInfo {
  functionId: NewFunctionId;
  version: string[];
}

model PatchInfo {
  comments: string[];
  id: string;
  modificationTime: string;
  urls: string[];
  version: string;
}

model LegalInstruction {
  licenseName: string;
  legalContent: string;
}

model Vulnerability {
  id: string;
  type?: VulnerabilityType;
  title: string;
  semver?: SemVerInfo;
  license?: string;
  legalInstructionsArray?: LegalInstruction[];
  language?: string;
  description: string;
  packageName?: string;
  packagePopularityRank?: int32;
  creationTime: string;
  packageManager?: string;
  publicationTime?: string;
  severity: VulnerabilitySeverity;
  severityWithCritical?: VulnerabilitySeverity;
  originalSeverity?: VulnerabilitySeverity;
  riskScore?: uint16;
  from: string[];
  reachability?: Reachability;
  reachablePaths?: ReachablePaths;
  upgradePath: UpgradePath[];
  isIgnored?: boolean;
  ignores?: VulnFilteredIgnored[];
  isUpgradable: boolean;
  isPatchable: boolean;
  isPinnable?: boolean;
  isRuntime?: boolean;
  name: string;
  version: string;
  CVSSv3?: string;
  alternativeIds?: string[];
  credit?: string[];
  cvssDetails?: CVSSDetail[];
  cvssScore?: float32;
  cvssSources?: CVSSSource[];
  disclosureTime?: string;
  epssDetails?: EPSSDetails;
  exploit?: string;
  exploitDetails?: ExploitDetails;
  fixedIn?: string[];
  functions?: FunctionInfo[];
  functions_new?: NewFunctionInfo[];
  identifiers?: Identifiers;
  insights?: Insights;
  isDisputed?: boolean;
  malicious?: boolean;
  modificationTime?: string;
  moduleName?: string;
  patches?: PatchInfo[];
  proprietary?: boolean;
  references?: Reference[];
  severityBasedOn?: string;
  socialTrendAlert?: boolean;
  patch?: string[];
  filtered?: VulnFiltered;
  appliedPolicyRules?: AppliedPolicyRules;
  securityPolicyMetaData?: SecurityPolicyMetaData;
  mavenModuleName?: MavenModuleName;
}

model MavenModuleName {
  groupId: string;
  artifactId: string;
}

model SecurityPolicyMetaData {
  ignore: VulnFilteredIgnored;
}

model AppliedPolicyRules {
  ignore?: AppliedPolicyRulesIgnore;
  severityChange?: AppliedPolicyRulesSeverityChange;
  "severity-override"?: AppliedPolicyRulesSeverityChange;
}

model AppliedPolicyRulesIgnore {
  id: string;
  type: string;
  ignore: VulnFilteredIgnored;
  policy: Policy;
  rule: IgnorePolicyRule;
}

model AppliedPolicyRulesSeverityChange {
  id: string;
  type: string;
  rule: SeverityChangePolicyRule;
  policy: Policy;
  originalSeverity: string;
  severity: string;
  newSeverity: string;
}

model AbstractPolicyRule {
  id: string;
  type: string;
}

model IgnorePolicyRule is AbstractPolicyRule {
  attributes: IgnorePolicyRuleAttributes;
}

model SeverityChangePolicyRule is AbstractPolicyRule {
  attributes: SeverityChangePolicyRuleAttributes;
}

model AbstractRuleAttributes {
  created: string;
  modified: string;
  name: string;
  review: string;
}

model IgnorePolicyRuleAttributes is AbstractRuleAttributes {
  actions: IgnorePolicyRuleAction[];
}

model SeverityChangePolicyRuleAttributes is AbstractRuleAttributes {
  actions: SeverityChangePolicyRuleAction[];
}

model SeverityChangePolicyRuleAction {
  type: string;
  data: SeverityChangePolicyRuleActionData;
}

model SeverityChangePolicyRuleActionData {
  severity: string;
}

model IgnorePolicyRuleAction {
  type: string;
  data: IgnorePolicyRuleActionData;
}

model IgnorePolicyRuleActionData {
  ignore_type: string;
  reason: string;
  source: string;
}

model Policy {
  id: string;
  owner: string;
}

model VulnFiltered {
  ignored?: VulnFilteredIgnored[];
}

model VulnFilteredIgnored {
  reason: string;
  expires?: string;
  created: string;
  source: string;
  path: unknown[];
  ignoredBy?: VulnFilteredIgnoredBy;
  disregardIfFixable?: boolean;
  reasonType?: string;
}

model VulnFilteredIgnoredBy {
  id: string;
  name: string;
  email: string | null;
  isGroupPolicy: boolean;
  type?: string;
}


model CVSSDetail {
  assigner: string;
  cvssV3BaseScore?: float32;
  cvssV3Vector?: string;
  modificationTime?: string;
  severity?: string;
}

model CVSSSource {
  assigner?: string;
  baseScore?: float32;
  cvssVersion?: string;
  modificationTime?: string;
  severity?: string;
  type?: string;
  vector?: string;
}

model Reference {
  title: string;
  url: string;
}

model Identifiers {
  ALTERNATIVE?: string[];
  CVE: string[];
  CWE: string[];
  GHSA?: string[];
  NSP?: string[];
  SNYK?: string[];
}

model EPSSDetails {
  modelVersion?: string;
  percentile?: string;
  probability?: string;
}

model ExploitMaturityLevel {
  format: string;
  level: string;
  type: string;
}

model ExploitDetails {
  maturityLevels: ExploitMaturityLevel[];
  sources: string[];
}

model Insights {
  triageAdvice?: string | null;
}

model LicenseRule {
  licenseType: string;
  severity: string;
  instructions: string;
}

model Severity {}

model LicensesPolicy {
  severities: Record<Severity>;
  orgLicenseRules: Record<LicenseRule>;
}

model IgnoreSettings {
  adminOnly: boolean;
  reasonRequired: boolean;
  disregardFilesystemIgnores: boolean;
  autoApproveIgnores: boolean;
}

model Filtered {
  ignore: Vulnerability[];
  patch: string[];
}

model RemediationUpgradeInfo {
  upgradeTo: string;
  upgrades: string[];
  vulns: string[];
}

model PinRemediation {
  isTransitive: boolean;
  vulns: string[];
  upgradeTo: string;
}

model Remediation {
  ignore: Record<string>;
  pin: Record<PinRemediation>;
  unresolved: Vulnerability[];
  upgrade: Record<RemediationUpgradeInfo>;
}

model LegacyVulnerabilityResponse {
  vulnerabilities: Vulnerability[];
  ok: boolean;
  dependencyCount: int64;
  foundProjectCount?: int32;
  projectId?: string;
  org: string;
  policy: string;
  isPrivate: boolean;
  licensesPolicy: LicensesPolicy;
  packageManager?: string;
  ignoreSettings: IgnoreSettings;
  summary: string;
  filesystemPolicy: boolean;
  filtered: Filtered;
  uniqueCount: int32;
  targetFile?: string;
  projectName?: string;
  displayTargetFile: string;
  hasUnknownVersions: boolean;
  path: string;
  remediation?: Remediation;
}
