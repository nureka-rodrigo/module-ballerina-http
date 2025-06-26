/*
 *  Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 *  OF ANY KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.stdlib.http.compiler.staticcodeanalyzer;

import io.ballerina.compiler.syntax.tree.ClientResourceAccessActionNode;
import io.ballerina.compiler.syntax.tree.ComputedResourceAccessSegmentNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FieldAccessExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionDefinitionNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.RecordFieldNode;
import io.ballerina.compiler.syntax.tree.RecordTypeDescriptorNode;
import io.ballerina.compiler.syntax.tree.RequiredParameterNode;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import static io.ballerina.stdlib.http.compiler.staticcodeanalyzer.HttpRule.AVOID_TRAVERSING_ATTACKS;

class HttpClientAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;

    public HttpClientAnalyzer(Reporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        ClientResourceAccessActionNode clientResourceAccessActionNode = (ClientResourceAccessActionNode) context.node();
        SeparatedNodeList<Node> resourceAccessPaths = clientResourceAccessActionNode.resourceAccessPath();

        resourceAccessPaths.stream().forEach(resourceAccessPath -> {
            if (resourceAccessPath instanceof ComputedResourceAccessSegmentNode computedResourceAccessSegment) {
                ExpressionNode expression = computedResourceAccessSegment.expression();

                switch (expression) {
                    case FieldAccessExpressionNode fieldAccessExpression:
                        if (isUserControlledInput(fieldAccessExpression.fieldName())) {
                            report(context, AVOID_TRAVERSING_ATTACKS.getId());
                        }
                        break;
                    case SimpleNameReferenceNode simpleNameReference:
                        if (isUserControlledInput(simpleNameReference)) {
                            report(context, AVOID_TRAVERSING_ATTACKS.getId());
                        }
                        break;
                    default:
                        // No action needed for other expression types
                }
            }
        });
    }

    /**
     * Checks if the given node is a user-controlled input.
     *
     * @param node the syntax node to check
     * @return true if the node is a user-controlled input, false otherwise
     */
    private boolean isUserControlledInput(Node node) {
        Node parent = node.parent();

        while (parent != null) {
            if (parent instanceof FunctionDefinitionNode functionDefinition) {
                return functionDefinition.functionSignature().parameters().stream()
                        .anyMatch(parameter -> {
                            if (parameter instanceof RequiredParameterNode requiredParameter &&
                                    requiredParameter.paramName().isPresent()) {
                                if (requiredParameter.typeName()
                                        instanceof RecordTypeDescriptorNode recordTypeDescriptor) {
                                    return recordTypeDescriptor.fields().stream()
                                            .anyMatch(field -> field instanceof RecordFieldNode recordField &&
                                                    recordField.fieldName().text().equals(node.toSourceCode()));
                                } else {
                                    String paramName = requiredParameter.paramName().get().text();
                                    return node.toSourceCode().equals(paramName);
                                }
                            }
                            return false;
                        });
            }
            parent = parent.parent();
        }

        return false;
    }

    /**
     * Reports an issue for the given context and rule ID.
     *
     * @param context the syntax node analysis context
     * @param ruleId  the ID of the rule to report
     */
    private void report(SyntaxNodeAnalysisContext context, int ruleId) {
        reporter.reportIssue(
                getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
                context.node().location(),
                ruleId
        );
    }

    /**
     * Retrieves the Document corresponding to the given module and document ID.
     *
     * @param module     the module
     * @param documentId the document ID
     * @return the Document for the given module and document ID
     */
    private static Document getDocument(Module module, DocumentId documentId) {
        return module.document(documentId);
    }
}
