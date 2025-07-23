// Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org)
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;

type User record {
    string username;
    string password;
    string role;
};

service on new http:Listener(8080) {
    resource function post .(http:Request request) returns json|error {
        json payload = check request.getJsonPayload();
        User user = check payload.cloneWithType(User);
        string message = string `User ${user.username} with role ${user.role} processed`;
        return {
            status: "success",
            message: message
        };
    }
}
