const pathology = require("./pathology_grpc_web_pb.js");
const extension = require("./extension_grpc_web_pb.js");

const grpcServerAddress = '/';
const extensionClient = new extension.ExtensionHostServicePromiseClient(grpcServerAddress, null, null);
const pathologyClient = new pathology.CorePromiseClient(grpcServerAddress, null, null);

module.exports = { extensionClient ,pathologyClient};