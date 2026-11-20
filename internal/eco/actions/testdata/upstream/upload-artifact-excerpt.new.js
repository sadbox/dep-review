/***/ 2822:
/***/ ((module) => {

module.exports = /*#__PURE__*/JSON.parse('{"name":"@actions/artifact","version":"6.3.1","preview":true,"description":"Actions artifact lib","keywords":["github","actions","artifact"],"homepage":"https://github.com/actions/toolkit/tree/main/packages/artifact","license":"MIT","type":"module","main":"lib/artifact.js","types":"lib/artifact.d.ts","exports":{".":{"types":"./lib/artifact.d.ts","import":"./lib/artifact.js"}},"directories":{"lib":"lib","test":"__tests__"},"files":["lib","!.DS_Store"],"publishConfig":{"access":"public"},"repository":{"type":"git","url":"git+https://github.com/actions/toolkit.git","directory":"packages/artifact"},"scripts":{"audit-moderate":"npm install && npm audit --json --audit-level=moderate > audit.json","test":"cd ../../ && npm run test ./packages/artifact","bootstrap":"cd ../../ && npm run bootstrap","tsc-run":"tsc && cp src/internal/shared/package-version.cjs lib/internal/shared/","tsc":"npm run bootstrap && npm run tsc-run","gen:docs":"typedoc --plugin typedoc-plugin-markdown --out docs/generated src/artifact.ts --githubPages false --readme none"},"bugs":{"url":"https://github.com/actions/toolkit/issues"},"dependencies":{"@actions/core":"^3.0.1","@actions/github":"^9.1.1","@actions/http-client":"^4.0.1","@azure/storage-blob":"^12.31.0","@octokit/core":"^7.0.6","@octokit/plugin-request-log":"^6.0.0","@octokit/plugin-retry":"^8.1.0","@octokit/request":"^10.0.8","@octokit/request-error":"^7.1.0","@protobuf-ts/runtime":"^2.11.1","@protobuf-ts/runtime-rpc":"^2.11.1","archiver":"^7.0.1","jwt-decode":"^4.0.0","unzip-stream":"^0.3.1"},"devDependencies":{"@protobuf-ts/plugin":"^2.11.1","@types/archiver":"^7.0.0","@types/unzip-stream":"^0.3.4","typedoc":"^0.28.19","typedoc-plugin-markdown":"^4.11.0","typescript":"^5.9.3"},"overrides":{"uri-js":"npm:uri-js-replace@^1.0.1","node-fetch":"^3.3.2"}}');

/***/ })

/******/ });
/************************************************************************/
/******/ // The module cache
/******/ var __webpack_module_cache__ = {};
/******/ 
/******/ // The require function
/******/ function __nccwpck_require__(moduleId) {
/******/ 	// Check if module is in cache
/******/ 	var cachedModule = __webpack_module_cache__[moduleId];
/******/ 	if (cachedModule !== undefined) {
/******/ 		return cachedModule.exports;
/******/ 	}
/******/ 	// Create a new module (and put it into the cache)
/******/ 	var module = __webpack_module_cache__[moduleId] = {
/******/ 		id: moduleId,
/******/ 		loaded: false,
/******/ 		exports: {}
/******/ 	};
/******/ 
/******/ 	// Execute the module function
/******/ 	var threw = true;
/******/ 	try {
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 		threw = false;
/******/ 	} finally {
/******/ 		if(threw) delete __webpack_module_cache__[moduleId];
/******/ 	}
/******/ 
/******/ 	// Flag the module as loaded
/******/ 	module.loaded = true;
/******/ 
/******/ 	// Return the exports of the module
/******/ 	return module.exports;
/******/ }
/******/ 
/************************************************************************/
/******/ /* webpack/runtime/create fake namespace object */
/******/ (() => {
/******/ 	var getProto = Object.getPrototypeOf ? (obj) => (Object.getPrototypeOf(obj)) : (obj) => (obj.__proto__);
/******/ 	var leafPrototypes;
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 16: return value when it's Promise-like
/******/ 	// mode & 8|1: behave like require
/******/ 	__nccwpck_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = this(value);
/******/ 		if(mode & 8) return value;
/******/ 		if(typeof value === 'object' && value) {
/******/ 			if((mode & 4) && value.__esModule) return value;
/******/ 			if((mode & 16) && typeof value.then === 'function') return value;
/******/ 		}
/******/ 		var ns = Object.create(null);
/******/ 		__nccwpck_require__.r(ns);
/******/ 		var def = {};
/******/ 		leafPrototypes = leafPrototypes || [null, getProto({}), getProto([]), getProto(getProto)];
/******/ 		for(var current = mode & 2 && value; typeof current == 'object' && !~leafPrototypes.indexOf(current); current = getProto(current)) {
/******/ 			Object.getOwnPropertyNames(current).forEach((key) => (def[key] = () => (value[key])));
/******/ 		}
/******/ 		def['default'] = () => (value);
/******/ 		__nccwpck_require__.d(ns, def);
/******/ 		return ns;
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/define property getters */
/******/ (() => {
/******/ 	// define getter functions for harmony exports
/******/ 	__nccwpck_require__.d = (exports, definition) => {
/******/ 		for(var key in definition) {
/******/ 			if(__nccwpck_require__.o(definition, key) && !__nccwpck_require__.o(exports, key)) {
/******/ 				Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 			}
/******/ 		}
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/hasOwnProperty shorthand */
/******/ (() => {
/******/ 	__nccwpck_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ })();
/******/ 
/******/ /* webpack/runtime/make namespace object */
/******/ (() => {
/******/ 	// define __esModule on exports
/******/ 	__nccwpck_require__.r = (exports) => {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/node module decorator */
/******/ (() => {
/******/ 	__nccwpck_require__.nmd = (module) => {
/******/ 		module.paths = [];
/******/ 		if (!module.children) module.children = [];
/******/ 		return module;
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/compat */
/******/ 
/******/ if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = new URL('.', import.meta.url).pathname.slice(import.meta.url.match(/^file:\/\/\/\w:/) ? 1 : 0, -1) + "/";
/******/ 
/************************************************************************/
var __webpack_exports__ = {};

// NAMESPACE OBJECT: ./node_modules/@azure/storage-blob/dist/esm/generated/src/models/mappers.js
var mappers_namespaceObject = {};
__nccwpck_require__.r(mappers_namespaceObject);
__nccwpck_require__.d(mappers_namespaceObject, {
  AccessPolicy: () => (AccessPolicy),
  AppendBlobAppendBlockExceptionHeaders: () => (AppendBlobAppendBlockExceptionHeaders),
  AppendBlobAppendBlockFromUrlExceptionHeaders: () => (AppendBlobAppendBlockFromUrlExceptionHeaders),
  AppendBlobAppendBlockFromUrlHeaders: () => (AppendBlobAppendBlockFromUrlHeaders),
  AppendBlobAppendBlockHeaders: () => (AppendBlobAppendBlockHeaders),
  AppendBlobCreateExceptionHeaders: () => (AppendBlobCreateExceptionHeaders),
  AppendBlobCreateHeaders: () => (AppendBlobCreateHeaders),
  AppendBlobSealExceptionHeaders: () => (AppendBlobSealExceptionHeaders),
  AppendBlobSealHeaders: () => (AppendBlobSealHeaders),
  ArrowConfiguration: () => (ArrowConfiguration),
  ArrowField: () => (ArrowField),
  BlobAbortCopyFromURLExceptionHeaders: () => (BlobAbortCopyFromURLExceptionHeaders),
  BlobAbortCopyFromURLHeaders: () => (BlobAbortCopyFromURLHeaders),
  BlobAcquireLeaseExceptionHeaders: () => (BlobAcquireLeaseExceptionHeaders),
  BlobAcquireLeaseHeaders: () => (BlobAcquireLeaseHeaders),
  BlobBreakLeaseExceptionHeaders: () => (BlobBreakLeaseExceptionHeaders),
  BlobBreakLeaseHeaders: () => (BlobBreakLeaseHeaders),
  BlobChangeLeaseExceptionHeaders: () => (BlobChangeLeaseExceptionHeaders),
  BlobChangeLeaseHeaders: () => (BlobChangeLeaseHeaders),
  BlobCopyFromURLExceptionHeaders: () => (BlobCopyFromURLExceptionHeaders),
  BlobCopyFromURLHeaders: () => (BlobCopyFromURLHeaders),
  BlobCreateSnapshotExceptionHeaders: () => (BlobCreateSnapshotExceptionHeaders),
  BlobCreateSnapshotHeaders: () => (BlobCreateSnapshotHeaders),
  BlobDeleteExceptionHeaders: () => (BlobDeleteExceptionHeaders),
  BlobDeleteHeaders: () => (BlobDeleteHeaders),
  BlobDeleteImmutabilityPolicyExceptionHeaders: () => (BlobDeleteImmutabilityPolicyExceptionHeaders),
  BlobDeleteImmutabilityPolicyHeaders: () => (BlobDeleteImmutabilityPolicyHeaders),
  BlobDownloadExceptionHeaders: () => (BlobDownloadExceptionHeaders),
  BlobDownloadHeaders: () => (BlobDownloadHeaders),
  BlobFlatListSegment: () => (BlobFlatListSegment),
  BlobGetAccountInfoExceptionHeaders: () => (BlobGetAccountInfoExceptionHeaders),
  BlobGetAccountInfoHeaders: () => (BlobGetAccountInfoHeaders),
  BlobGetPropertiesExceptionHeaders: () => (BlobGetPropertiesExceptionHeaders),
  BlobGetPropertiesHeaders: () => (BlobGetPropertiesHeaders),
  BlobGetTagsExceptionHeaders: () => (BlobGetTagsExceptionHeaders),
  BlobGetTagsHeaders: () => (BlobGetTagsHeaders),
  BlobHierarchyListSegment: () => (BlobHierarchyListSegment),
  BlobItemInternal: () => (BlobItemInternal),
  BlobName: () => (BlobName),
  BlobPrefix: () => (BlobPrefix),
  BlobPropertiesInternal: () => (BlobPropertiesInternal),
  BlobQueryExceptionHeaders: () => (BlobQueryExceptionHeaders),
  BlobQueryHeaders: () => (BlobQueryHeaders),
  BlobReleaseLeaseExceptionHeaders: () => (BlobReleaseLeaseExceptionHeaders),
  BlobReleaseLeaseHeaders: () => (BlobReleaseLeaseHeaders),
  BlobRenewLeaseExceptionHeaders: () => (BlobRenewLeaseExceptionHeaders),
  BlobRenewLeaseHeaders: () => (BlobRenewLeaseHeaders),
  BlobServiceProperties: () => (BlobServiceProperties),
  BlobServiceStatistics: () => (BlobServiceStatistics),
  BlobSetExpiryExceptionHeaders: () => (BlobSetExpiryExceptionHeaders),
  BlobSetExpiryHeaders: () => (BlobSetExpiryHeaders),
  BlobSetHttpHeadersExceptionHeaders: () => (BlobSetHttpHeadersExceptionHeaders),
  BlobSetHttpHeadersHeaders: () => (BlobSetHttpHeadersHeaders),
  BlobSetImmutabilityPolicyExceptionHeaders: () => (BlobSetImmutabilityPolicyExceptionHeaders),
  BlobSetImmutabilityPolicyHeaders: () => (BlobSetImmutabilityPolicyHeaders),
  BlobSetLegalHoldExceptionHeaders: () => (BlobSetLegalHoldExceptionHeaders),
  BlobSetLegalHoldHeaders: () => (BlobSetLegalHoldHeaders),
  BlobSetMetadataExceptionHeaders: () => (BlobSetMetadataExceptionHeaders),
  BlobSetMetadataHeaders: () => (BlobSetMetadataHeaders),
  BlobSetTagsExceptionHeaders: () => (BlobSetTagsExceptionHeaders),
  BlobSetTagsHeaders: () => (BlobSetTagsHeaders),
  BlobSetTierExceptionHeaders: () => (BlobSetTierExceptionHeaders),
  BlobSetTierHeaders: () => (BlobSetTierHeaders),
  BlobStartCopyFromURLExceptionHeaders: () => (BlobStartCopyFromURLExceptionHeaders),
  BlobStartCopyFromURLHeaders: () => (BlobStartCopyFromURLHeaders),
  BlobTag: () => (BlobTag),
  BlobTags: () => (BlobTags),
  BlobUndeleteExceptionHeaders: () => (BlobUndeleteExceptionHeaders),
  BlobUndeleteHeaders: () => (BlobUndeleteHeaders),
  Block: () => (Block),
  BlockBlobCommitBlockListExceptionHeaders: () => (BlockBlobCommitBlockListExceptionHeaders),
  BlockBlobCommitBlockListHeaders: () => (BlockBlobCommitBlockListHeaders),
  BlockBlobGetBlockListExceptionHeaders: () => (BlockBlobGetBlockListExceptionHeaders),
  BlockBlobGetBlockListHeaders: () => (BlockBlobGetBlockListHeaders),
  BlockBlobPutBlobFromUrlExceptionHeaders: () => (BlockBlobPutBlobFromUrlExceptionHeaders),
  BlockBlobPutBlobFromUrlHeaders: () => (BlockBlobPutBlobFromUrlHeaders),
  BlockBlobStageBlockExceptionHeaders: () => (BlockBlobStageBlockExceptionHeaders),
  BlockBlobStageBlockFromURLExceptionHeaders: () => (BlockBlobStageBlockFromURLExceptionHeaders),
  BlockBlobStageBlockFromURLHeaders: () => (BlockBlobStageBlockFromURLHeaders),
  BlockBlobStageBlockHeaders: () => (BlockBlobStageBlockHeaders),
  BlockBlobUploadExceptionHeaders: () => (BlockBlobUploadExceptionHeaders),
  BlockBlobUploadHeaders: () => (BlockBlobUploadHeaders),
  BlockList: () => (BlockList),
  BlockLookupList: () => (BlockLookupList),
  ClearRange: () => (ClearRange),
  ContainerAcquireLeaseExceptionHeaders: () => (ContainerAcquireLeaseExceptionHeaders),
  ContainerAcquireLeaseHeaders: () => (ContainerAcquireLeaseHeaders),
  ContainerBreakLeaseExceptionHeaders: () => (ContainerBreakLeaseExceptionHeaders),
  ContainerBreakLeaseHeaders: () => (ContainerBreakLeaseHeaders),
  ContainerChangeLeaseExceptionHeaders: () => (ContainerChangeLeaseExceptionHeaders),
  ContainerChangeLeaseHeaders: () => (ContainerChangeLeaseHeaders),
  ContainerCreateExceptionHeaders: () => (ContainerCreateExceptionHeaders),
  ContainerCreateHeaders: () => (ContainerCreateHeaders),
  ContainerDeleteExceptionHeaders: () => (ContainerDeleteExceptionHeaders),
  ContainerDeleteHeaders: () => (ContainerDeleteHeaders),
  ContainerFilterBlobsExceptionHeaders: () => (ContainerFilterBlobsExceptionHeaders),
  ContainerFilterBlobsHeaders: () => (ContainerFilterBlobsHeaders),
  ContainerGetAccessPolicyExceptionHeaders: () => (ContainerGetAccessPolicyExceptionHeaders),
  ContainerGetAccessPolicyHeaders: () => (ContainerGetAccessPolicyHeaders),
  ContainerGetAccountInfoExceptionHeaders: () => (ContainerGetAccountInfoExceptionHeaders),
  ContainerGetAccountInfoHeaders: () => (ContainerGetAccountInfoHeaders),
  ContainerGetPropertiesExceptionHeaders: () => (ContainerGetPropertiesExceptionHeaders),
  ContainerGetPropertiesHeaders: () => (ContainerGetPropertiesHeaders),
  ContainerItem: () => (ContainerItem),
  ContainerListBlobFlatSegmentExceptionHeaders: () => (ContainerListBlobFlatSegmentExceptionHeaders),
  ContainerListBlobFlatSegmentHeaders: () => (ContainerListBlobFlatSegmentHeaders),
  ContainerListBlobHierarchySegmentExceptionHeaders: () => (ContainerListBlobHierarchySegmentExceptionHeaders),
  ContainerListBlobHierarchySegmentHeaders: () => (ContainerListBlobHierarchySegmentHeaders),
  ContainerProperties: () => (ContainerProperties),
  ContainerReleaseLeaseExceptionHeaders: () => (ContainerReleaseLeaseExceptionHeaders),
  ContainerReleaseLeaseHeaders: () => (ContainerReleaseLeaseHeaders),
  ContainerRenameExceptionHeaders: () => (ContainerRenameExceptionHeaders),
  ContainerRenameHeaders: () => (ContainerRenameHeaders),
  ContainerRenewLeaseExceptionHeaders: () => (ContainerRenewLeaseExceptionHeaders),
  ContainerRenewLeaseHeaders: () => (ContainerRenewLeaseHeaders),
  ContainerRestoreExceptionHeaders: () => (ContainerRestoreExceptionHeaders),
  ContainerRestoreHeaders: () => (ContainerRestoreHeaders),
  ContainerSetAccessPolicyExceptionHeaders: () => (ContainerSetAccessPolicyExceptionHeaders),
  ContainerSetAccessPolicyHeaders: () => (ContainerSetAccessPolicyHeaders),
  ContainerSetMetadataExceptionHeaders: () => (ContainerSetMetadataExceptionHeaders),
  ContainerSetMetadataHeaders: () => (ContainerSetMetadataHeaders),
  ContainerSubmitBatchExceptionHeaders: () => (ContainerSubmitBatchExceptionHeaders),
  ContainerSubmitBatchHeaders: () => (ContainerSubmitBatchHeaders),
  CorsRule: () => (CorsRule),
  DelimitedTextConfiguration: () => (DelimitedTextConfiguration),
  FilterBlobItem: () => (FilterBlobItem),
  FilterBlobSegment: () => (FilterBlobSegment),
  GeoReplication: () => (GeoReplication),
  JsonTextConfiguration: () => (JsonTextConfiguration),
  KeyInfo: () => (KeyInfo),
  ListBlobsFlatSegmentResponse: () => (ListBlobsFlatSegmentResponse),
  ListBlobsHierarchySegmentResponse: () => (ListBlobsHierarchySegmentResponse),
  ListContainersSegmentResponse: () => (ListContainersSegmentResponse),
  Logging: () => (Logging),
  Metrics: () => (Metrics),
  PageBlobClearPagesExceptionHeaders: () => (PageBlobClearPagesExceptionHeaders),
  PageBlobClearPagesHeaders: () => (PageBlobClearPagesHeaders),
  PageBlobCopyIncrementalExceptionHeaders: () => (PageBlobCopyIncrementalExceptionHeaders),
  PageBlobCopyIncrementalHeaders: () => (PageBlobCopyIncrementalHeaders),
  PageBlobCreateExceptionHeaders: () => (PageBlobCreateExceptionHeaders),
  PageBlobCreateHeaders: () => (PageBlobCreateHeaders),
  PageBlobGetPageRangesDiffExceptionHeaders: () => (PageBlobGetPageRangesDiffExceptionHeaders),
  PageBlobGetPageRangesDiffHeaders: () => (PageBlobGetPageRangesDiffHeaders),
  PageBlobGetPageRangesExceptionHeaders: () => (PageBlobGetPageRangesExceptionHeaders),
  PageBlobGetPageRangesHeaders: () => (PageBlobGetPageRangesHeaders),
  PageBlobResizeExceptionHeaders: () => (PageBlobResizeExceptionHeaders),
  PageBlobResizeHeaders: () => (PageBlobResizeHeaders),
  PageBlobUpdateSequenceNumberExceptionHeaders: () => (PageBlobUpdateSequenceNumberExceptionHeaders),
  PageBlobUpdateSequenceNumberHeaders: () => (PageBlobUpdateSequenceNumberHeaders),
  PageBlobUploadPagesExceptionHeaders: () => (PageBlobUploadPagesExceptionHeaders),
  PageBlobUploadPagesFromURLExceptionHeaders: () => (PageBlobUploadPagesFromURLExceptionHeaders),
  PageBlobUploadPagesFromURLHeaders: () => (PageBlobUploadPagesFromURLHeaders),
  PageBlobUploadPagesHeaders: () => (PageBlobUploadPagesHeaders),
  PageList: () => (PageList),
  PageRange: () => (PageRange),
  QueryFormat: () => (QueryFormat),
  QueryRequest: () => (QueryRequest),
  QuerySerialization: () => (QuerySerialization),
  RetentionPolicy: () => (RetentionPolicy),
  ServiceFilterBlobsExceptionHeaders: () => (ServiceFilterBlobsExceptionHeaders),
  ServiceFilterBlobsHeaders: () => (ServiceFilterBlobsHeaders),
  ServiceGetAccountInfoExceptionHeaders: () => (ServiceGetAccountInfoExceptionHeaders),
  ServiceGetAccountInfoHeaders: () => (ServiceGetAccountInfoHeaders),
  ServiceGetPropertiesExceptionHeaders: () => (ServiceGetPropertiesExceptionHeaders),
  ServiceGetPropertiesHeaders: () => (ServiceGetPropertiesHeaders),
  ServiceGetStatisticsExceptionHeaders: () => (ServiceGetStatisticsExceptionHeaders),
  ServiceGetStatisticsHeaders: () => (ServiceGetStatisticsHeaders),
  ServiceGetUserDelegationKeyExceptionHeaders: () => (ServiceGetUserDelegationKeyExceptionHeaders),
  ServiceGetUserDelegationKeyHeaders: () => (ServiceGetUserDelegationKeyHeaders),
  ServiceListContainersSegmentExceptionHeaders: () => (ServiceListContainersSegmentExceptionHeaders),
  ServiceListContainersSegmentHeaders: () => (ServiceListContainersSegmentHeaders),
  ServiceSetPropertiesExceptionHeaders: () => (ServiceSetPropertiesExceptionHeaders),
  ServiceSetPropertiesHeaders: () => (ServiceSetPropertiesHeaders),
  ServiceSubmitBatchExceptionHeaders: () => (ServiceSubmitBatchExceptionHeaders),
  ServiceSubmitBatchHeaders: () => (ServiceSubmitBatchHeaders),
  SignedIdentifier: () => (SignedIdentifier),
  StaticWebsite: () => (StaticWebsite),
  StorageError: () => (StorageError),
  UserDelegationKey: () => (UserDelegationKey)
});

// EXTERNAL MODULE: external "os"
var external_os_ = __nccwpck_require__(857);
;// CONCATENATED MODULE: ./node_modules/@actions/core/lib/utils.js
// We use any as a valid input type
/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Sanitizes an input into a string so it can be passed into issueCommand safely
 * @param input input to sanitize into a string
 */
function utils_toCommandValue(input) {
    if (input === null || input === undefined) {
        return '';
    }
    else if (typeof input === 'string' || input instanceof String) {
        return input;
    }
    return JSON.stringify(input);
}
/**
 *
 * @param annotationProperties
 * @returns The command properties to send with the actual annotation command
 * See IssueCommandProperties: https://github.com/actions/runner/blob/main/src/Runner.Worker/ActionCommandManager.cs#L646
 */
function utils_toCommandProperties(annotationProperties) {
    if (!Object.keys(annotationProperties).length) {
        return {};
    }
    return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
    };
}
//# sourceMappingURL=utils.js.map
;// CONCATENATED MODULE: ./node_modules/@actions/artifact/lib/internal/shared/errors.js
class FilesNotFoundError extends Error {
    constructor(files = []) {
        let message = 'No files were found to upload';
        if (files.length > 0) {
            message += `: ${files.join(', ')}`;
        }
        super(message);
        this.files = files;
        this.name = 'FilesNotFoundError';
    }
}
class InvalidResponseError extends Error {
    constructor(message) {
        super(message);
        this.name = 'InvalidResponseError';
    }
}
class ArtifactNotFoundError extends Error {
    constructor(message = 'Artifact not found') {
        super(message);
        this.name = 'ArtifactNotFoundError';
    }
}
class GHESNotSupportedError extends Error {
    constructor(message = '@actions/artifact v2.0.0+, upload-artifact@v4+ and download-artifact@v4+ are not currently supported on GHES.') {
        super(message);
        this.name = 'GHESNotSupportedError';
    }
}
class NetworkError extends Error {
    constructor(code) {
        const message = `Unable to make request: ${code}\nIf you are using self-hosted runners, please make sure your runner has access to all GitHub endpoints: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#communication-between-self-hosted-runners-and-github`;
        super(message);
        this.code = code;
        this.name = 'NetworkError';
    }
}
NetworkError.isNetworkErrorCode = (code) => {
    if (!code)
        return false;
    return [
        'ECONNRESET',
        'ENOTFOUND',
        'ETIMEDOUT',
        'ECONNREFUSED',
        'EHOSTUNREACH'
    ].includes(code);
};
class UsageError extends Error {
    constructor() {
        const message = `Artifact storage quota has been hit. Unable to upload any new artifacts.\nMore info on storage limits: https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions#calculating-minute-and-storage-spending`;
        super(message);
        this.name = 'UsageError';
    }
}
UsageError.isUsageErrorMessage = (msg) => {
    if (!msg)
        return false;
    return msg.includes('insufficient usage');
};
//# sourceMappingURL=errors.js.map
;// CONCATENATED MODULE: ./node_modules/@actions/github/lib/utils.js


// octokit + plugins



const utils_context = new Context();
const baseUrl = getApiBaseUrl();
const defaults = {
    baseUrl,
    request: {
        agent: getProxyAgent(baseUrl),
        fetch: getProxyFetch(baseUrl)
    }
};
const GitHub = Octokit.plugin(restEndpointMethods, paginateRest).defaults(defaults);

/**
 * Convience function to correctly format Octokit Options to pass into the constructor.
 *
 * @param     token    the repo PAT or GITHUB_TOKEN
 * @param     options  other options to set
 */
function getOctokitOptions(token, options) {
    const opts = Object.assign({}, options || {}); // Shallow clone - don't mutate the object provided by the caller
    // Auth
    const auth = getAuthString(token, opts);
    if (auth) {
        opts.auth = auth;
    }
    // Orchestration ID
    const userAgent = getUserAgentWithOrchestrationId(opts.userAgent);
    if (userAgent) {
        opts.userAgent = userAgent;
    }
    return opts;
}
//# sourceMappingURL=utils.js.map
