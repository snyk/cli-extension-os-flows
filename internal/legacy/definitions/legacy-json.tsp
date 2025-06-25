model SemVerInfo {
  vulnerable: string[];
  vulnerableHashes?: string[];
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

model Vulnerability {
  id: string;
  type?: VulnerabilityType;
  title: string;
  semver?: SemVerInfo;
  license?: string;
  language?: string;
  description: string;
  packageName?: string;
  packagePopularityRank?: int32;
  creationTime: string;
  packageManager?: string;
  publicationTime?: string;
  severity: VulnerabilitySeverity;
  severityWithCritical?: VulnerabilitySeverity;
  riskScore?: uint16;
  from: string[];
  upgradePath: UpgradePath[];
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
  epssDetails?: EPSDetails | null;
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
}

model VulnFiltered {
  ignored?: VulnFilteredIgnored[];
}

model VulnFilteredIgnored {
  reason: string;
  expires: string;
  created: string;
  source: string;
  path: string[];
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

model EPSDetails {
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

model Remediation {
  ignore: Record<string>;
  patch: Record<string>;
  pin: Record<string>;
  unresolved: Vulnerability[];
  upgrade: Record<RemediationUpgradeInfo>;
}

model LegacyVulnerabilityResponse {
  vulnerabilities: Vulnerability[];
  ok: boolean;
  dependencyCount: int64;
  foundProjectCount?: int32;
  org: string;
  policy: string;
  isPrivate: boolean;
  licensesPolicy: LicensesPolicy;
  packageManager: string;
  ignoreSettings: IgnoreSettings;
  summary: string;
  filesystemPolicy: boolean;
  filtered: Filtered;
  uniqueCount: int32;
  targetFile?: string;
  projectName: string;
  displayTargetFile: string;
  hasUnknownVersions: boolean;
  path: string;
  remediation?: Remediation;
}
