/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.stdlib.http.compiler.staticcodeanalyzer;

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.ParameterSymbol;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.TypeReferenceTypeSymbol;
import io.ballerina.compiler.syntax.tree.CheckExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.MethodCallExpressionNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.Optional;

import static io.ballerina.stdlib.http.compiler.staticcodeanalyzer.HttpRule.AVOID_VULNERABLE_DESERIALIZATION;

class HttpDeserializationAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private SemanticModel semanticModel = null;
    private static final String CLONE_WITH_TYPE = "cloneWithType";
    private static final String GET_JSON_PAYLOAD = "getJsonPayload";

    public HttpDeserializationAnalyzer(Reporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        MethodCallExpressionNode methodCallExpression = (MethodCallExpressionNode) context.node();
        semanticModel = context.semanticModel();
        if (!isMethodCallExpressionMatches(methodCallExpression, CLONE_WITH_TYPE)) {
            return;
        }
        if (!hasDeserialization(methodCallExpression)) {
            return;
        }
        if (!isVulnerableDeserialization(methodCallExpression)) {
            return;
        }
        report(context, AVOID_VULNERABLE_DESERIALIZATION.getId());
    }

    /**
     * Checks if the given method call expression matches the specified method name.
     *
     * @param methodCallExpression the method call expression to check
     * @param methodName           the method name to match against
     * @return true if the method call expression matches the method name, false otherwise
     */
    private boolean isMethodCallExpressionMatches(MethodCallExpressionNode methodCallExpression, String methodName) {
        return methodCallExpression.methodName().toString().trim().equals(methodName);
    }

    /**
     * Checks if the method call expression is part of a deserialization process.
     *
     * @param methodCallExpression the method call expression to check
     * @return true if the method call expression is part of a deserialization process, false otherwise
     */
    private boolean hasDeserialization(MethodCallExpressionNode methodCallExpression) {
        Node parent = methodCallExpression.parent();

        while (parent != null) {
            if (parent instanceof VariableDeclarationNode variableDeclaration
                    && variableDeclaration.initializer().isPresent()
                    && variableDeclaration.initializer().get() instanceof CheckExpressionNode checkExpression
                    && checkExpression.expression() instanceof MethodCallExpressionNode methodCallExpressionNode
                    && isMethodCallExpressionMatches(methodCallExpressionNode, CLONE_WITH_TYPE)) {
                Optional<Symbol> symbol = semanticModel.symbol(variableDeclaration.typedBindingPattern()
                        .typeDescriptor());
                if (symbol.isPresent() && symbol.get() instanceof TypeReferenceTypeSymbol) {
                    return true;
                }
            }
            parent = parent.parent();
        }
        return false;
    }

    /**
     * Checks if the method call expression is vulnerable to deserialization attacks.
     *
     * @param methodCallExpression the method call expression to check
     * @return true if the method call expression is vulnerable, false otherwise
     */
    private boolean isVulnerableDeserialization(MethodCallExpressionNode methodCallExpression) {
        String methodExpression = methodCallExpression.expression().toString().trim();
        Node parent = methodCallExpression.parent();

        while (parent != null) {
            if (parent instanceof FunctionBodyBlockNode functionBodyBlock) {
                for (var statement : functionBodyBlock.statements()) {
                    if (statement instanceof VariableDeclarationNode variableDeclaration
                            && variableDeclaration.typedBindingPattern().bindingPattern()
                            .toString().trim().equals(methodExpression)
                            && variableDeclaration.initializer().isPresent()
                            && variableDeclaration.initializer().get() instanceof CheckExpressionNode checkExpression
                            && checkExpression.expression() instanceof MethodCallExpressionNode methodCallExpressionNode
                            && isMethodCallExpressionMatches(methodCallExpressionNode, GET_JSON_PAYLOAD)
                            && isFromRequest(methodCallExpressionNode.expression())) {
                        return true;
                    }
                }
            }
            parent = parent.parent();
        }
        return false;
    }

    /**
     * Checks if the given node is from a request.
     *
     * @param node the syntax node to check
     * @return true if the node is from a request, false otherwise
     */
    private boolean isFromRequest(Node node) {
        Optional<Symbol> symbol = semanticModel.symbol(node);
        return symbol.filter(ParameterSymbol.class::isInstance).isPresent();
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
