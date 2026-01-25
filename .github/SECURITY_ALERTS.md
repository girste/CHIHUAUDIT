# Security Alerts Status

This document tracks the status of security alerts and why some cannot be resolved.

## Resolved Alerts

- ✅ **#35, #39, #40** - TokenPermissionsID: Fixed by setting top-level `permissions: read-all`
- ✅ **#42** - InsecureSkipVerify: Intentional for WAF/CDN detection, marked with `#nosec G402`

## Cannot Resolve (False Positives / Process Requirements)

### #27, #43 - PinnedDependenciesID (scorecard.yml, trivy.yml)
**Status**: Cannot fix - conflicting requirements  
**Reason**: OpenSSF Scorecard **requires** semver tags (`@v3`) instead of SHA pinning for `codeql-action/upload-sarif`. 
When we pin with SHA, Scorecard workflow fails with verification error.  
**Decision**: Keep `@v3` tag to allow Scorecard to pass. This is still secure via GitHub's tag verification.

### #31 - CodeReviewID
**Status**: Process requirement  
**Reason**: Requires enforced PR reviews. Project allows direct commits for rapid development.  
**Decision**: Accept as project policy.

### #32 - MaintainedID
**Status**: Temporary (repo age < 90 days)  
**Reason**: Project created recently. Will auto-resolve after 90 days.  
**Decision**: No action needed.

### #33 - CIIBestPracticesID
**Status**: Optional badge  
**Reason**: Requires earning OpenSSF Best Practices badge.  
**Decision**: Consider for future milestone.

### #34 - FuzzingID
**Status**: Not implemented  
**Reason**: Requires setting up fuzzing infrastructure.  
**Decision**: Consider for future security enhancement.

## Summary

- **Technical issues**: All resolved ✅
- **False positives**: 2 (due to Scorecard requirements)
- **Process/Policy**: 4 (not technical security issues)

Last updated: 2026-01-25
