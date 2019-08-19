/*
 *   Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.sql.rewriter.nestedfield;

import com.alibaba.druid.sql.ast.expr.SQLIdentifierExpr;
import com.alibaba.druid.sql.ast.statement.SQLExprTableSource;
import com.alibaba.druid.sql.ast.statement.SQLJoinTableSource;
import com.alibaba.druid.sql.ast.statement.SQLTableSource;
import com.alibaba.druid.sql.dialect.mysql.ast.statement.MySqlSelectQueryBlock;

import static com.alibaba.druid.sql.ast.statement.SQLJoinTableSource.JoinType.COMMA;

/**
 * Table (ES Index) expression in FROM statement.
 */
class From extends SQLClause<SQLTableSource> {

    From(SQLTableSource expr) {
        super(expr);
    }

    /**
     * Collect nested field(s) information and then remove them from FROM statement.
     * Assumption: only 1 regular table in FROM (which is the first one) and nested field(s) has alias.
     */
    @Override
    void rewrite(Scope scope) {
        if (!isCommaJoin() || parentAlias(scope).isEmpty()) {
            return;
        }

        collectNestedFields(scope);
        if (scope.isAnyNestedField()) {
            eraseParentAlias();
            keepParentTableOnly();
        }
    }

    private String parentAlias(Scope scope) {
        scope.setParentAlias(((SQLJoinTableSource) expr).getLeft().getAlias());
        return emptyIfNull(scope.getParentAlias());
    }

    /** Erase alias otherwise NLPchina has problem parsing nested field like 't.employees.name' */
    private void eraseParentAlias() {
        left().expr.setAlias(null);
    }

    private void keepParentTableOnly() {
        MySqlSelectQueryBlock query = (MySqlSelectQueryBlock) expr.getParent();
        query.setFrom(left().expr);
        left().expr.setParent(query);
    }

    /**
     * Collect path alias and full path mapping of nested field in FROM clause.
     * Sample:
     *  FROM team t, t.employees e ...
     *
     *         Join
     *        /    \
     *  team t    Join
     *           /    \
     *  t.employees e  ...
     *
     *  t.employees is nested because path "t" == parentAlias "t"
     *  Save path alias to full path name mapping {"e": "employees"} to Scope
     */
    private void collectNestedFields(Scope scope) {
        From clause = this;
        for (; clause.isCommaJoin(); clause = clause.right()) {
            clause.left().addIfNestedField(scope);
        }
        clause.addIfNestedField(scope);
    }

    private boolean isCommaJoin() {
        return expr instanceof SQLJoinTableSource && ((SQLJoinTableSource) expr).getJoinType() == COMMA;
    }

    private From left() {
        return new From(((SQLJoinTableSource) expr).getLeft());
    }

    private From right() {
        return new From(((SQLJoinTableSource) expr).getRight());
    }

    private void addIfNestedField(Scope scope) {
        if (!(expr instanceof SQLExprTableSource &&
                ((SQLExprTableSource) expr).getExpr() instanceof SQLIdentifierExpr)) {
            return;
        }

        Identifier table = new Identifier((SQLIdentifierExpr) ((SQLExprTableSource) expr).getExpr());

        // the top level parent table has an empty path. Don't add it to {alias -> path} mapping
        if (!table.path().isEmpty()) {
            String fullPath = scope.getFullPath(table.path());
            String prefix = fullPath.isEmpty() ? "" : fullPath + ".";
            scope.addAliasFullPath(emptyIfNull(expr.getAlias()), prefix + table.name());
        }
    }

    private String emptyIfNull(String str) {
        return str == null ? "" : str;
    }

}
