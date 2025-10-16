// Package localpolicy implements functions and type definitions around snyk's
// policy configuration files. These are commonly stored as YAML on a filesystem
// as .snyk files.
//
// This is a partial implementation of the TS library @snyk/policy, with many
// features missing. The focus of this implementation is on ignores.
// Also see https://github.com/snyk/policy.
package localpolicy
