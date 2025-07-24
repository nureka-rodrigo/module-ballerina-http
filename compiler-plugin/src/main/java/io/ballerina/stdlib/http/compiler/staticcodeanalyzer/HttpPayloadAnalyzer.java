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
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.TypeReferenceTypeSymbol;
import io.ballerina.compiler.syntax.tree.AnnotationNode;
import io.ballerina.compiler.syntax.tree.FunctionSignatureNode;
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ImportPrefixNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ParameterNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.compiler.syntax.tree.RequiredParameterNode;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

class HttpPayloadAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private SemanticModel semanticModel = null;
    private static final String BALLERINA_ORG = "ballerina";
    private static final String HTTP = "http";
    private static final String PAYLOAD = "Payload";

    private final Set<String> httpPrefixes = new HashSet<>();

    public HttpPayloadAnalyzer(Reporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        analyzeImports(context);
        semanticModel = context.semanticModel();
        FunctionSignatureNode functionSignature = (FunctionSignatureNode) context.node();
        if (functionSignature.parameters().isEmpty()) {
            return;
        }
        if (!isVulnerableHttpPayloadParameter(functionSignature.parameters())) {
            return;
        }
        report(context, HttpRule.AVOID_ENTITY_RECORDS_IN_RESOURCE_ARGUMENTS.getId());
    }

    private boolean isVulnerableHttpPayloadParameter(SeparatedNodeList<ParameterNode> parameters) {
        for (ParameterNode parameter : parameters) {
            if (!(parameter instanceof RequiredParameterNode requiredParameter)) {
                return false;
            }
            if (requiredParameter.annotations().isEmpty()) {
                return false;
            }
            for (AnnotationNode annotation : requiredParameter.annotations()) {
                if (annotation.annotReference() instanceof QualifiedNameReferenceNode qualifiedNameReference
                        && httpPrefixes.contains(qualifiedNameReference.modulePrefix().text().trim())
                        && qualifiedNameReference.identifier().text().trim().equals(PAYLOAD)
                        && requiredParameter.typeName() instanceof SimpleNameReferenceNode simpleNameReference
                        && isEntityRecord(simpleNameReference)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isEntityRecord(SimpleNameReferenceNode simpleNameReference) {
        Optional<Symbol> symbol = semanticModel.symbol(simpleNameReference);
        if (symbol.isEmpty()) {
            return false;
        }
        Symbol resolvedSymbol = symbol.get();
        return resolvedSymbol instanceof TypeReferenceTypeSymbol;
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

    /**
     * Analyzes imports to identify all prefixes used for the http module.
     *
     * @param context the syntax node analysis context
     */
    private void analyzeImports(SyntaxNodeAnalysisContext context) {
        Document document = getDocument(context.currentPackage().module(context.moduleId()), context.documentId());

        if (document.syntaxTree().rootNode() instanceof ModulePartNode modulePartNode) {
            modulePartNode.imports().forEach(importDeclarationNode -> {
                ImportOrgNameNode importOrgNameNode = importDeclarationNode.orgName().orElse(null);

                if (importOrgNameNode != null && BALLERINA_ORG.equals(importOrgNameNode.orgName().text())
                        && importDeclarationNode.moduleName().stream()
                        .anyMatch(moduleNameNode -> HTTP.equals(moduleNameNode.text()))) {

                    ImportPrefixNode importPrefixNode = importDeclarationNode.prefix().orElse(null);
                    String prefix = importPrefixNode != null ? importPrefixNode.prefix().text() : HTTP;

                    httpPrefixes.add(prefix);
                }
            });
        }
    }
}
