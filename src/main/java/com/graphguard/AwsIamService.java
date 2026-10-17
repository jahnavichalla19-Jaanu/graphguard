package com.graphguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class AwsIamService {
    private static final Logger log = LoggerFactory.getLogger(AwsIamService.class);
    private static final Set<String> COMPUTE_ACTIONS = Set.of(
            "lambda:CreateFunction",
            "ec2:RunInstances",
            "cloudformation:CreateStack",
            "glue:CreateDevEndpoint"
    );
    private static final Set<String> SENSITIVE_KEYWORDS = Set.of(
            "customer", "prod", "production", "secret", "billing", "sensitive", "payment", "database", "db"
    );

    private final ObjectMapper json = new ObjectMapper();

    public record PolicyStatement(
            String effect,
            Set<String> actions,
            Set<String> notActions,
            Set<String> resources,
            Set<String> notResources,
            Map<String, Map<String, List<String>>> conditions
    ) {
        public boolean isAllow() {
            return "Allow".equalsIgnoreCase(effect);
        }

        public boolean isDeny() {
            return "Deny".equalsIgnoreCase(effect);
        }
    }

    public record OidcTrustInfo(
            boolean trustsGithub,
            String audience,
            List<String> subPatterns,
            boolean missingSub,
            boolean overPermissive,
            String overPermissiveReason
    ) {}

    public record ParsedRole(
            String name,
            String arn,
            boolean isAdmin,
            OidcTrustInfo oidcTrust,
            List<PolicyStatement> statements,
            Set<String> attachedManagedPolicies,
            Set<String> trustedRoleArns
    ) {}

    public record ParsedResource(
            String name,
            String arn,
            String type,
            boolean sensitive,
            String executesAsRole
    ) {}

    public record IamParseResult(
            Map<String, ParsedRole> roles,
            Map<String, ParsedResource> resources,
            List<String> warnings
    ) {}

    public boolean isAwsAuthDetails(String rawJson) {
        if (rawJson == null || rawJson.isBlank()) {
            return false;
        }
        try {
            JsonNode root = json.readTree(rawJson);
            return root.has("RoleDetailList") || root.has("UserDetailList")
                    || root.has("GroupDetailList") || root.has("Policies");
        } catch (Exception e) {
            return false;
        }
    }

    public IamParseResult parseAuthorizationDetails(String rawJson) {
        JsonNode root;
        try {
            root = json.readTree(rawJson);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid AWS IAM JSON: " + e.getMessage());
        }

        Map<String, List<PolicyStatement>> managedPolicyStatements = new LinkedHashMap<>();
        for (JsonNode pol : root.path("Policies")) {
            String arn = pol.path("Arn").asText("");
            String polName = pol.path("PolicyName").asText("");
            List<PolicyStatement> stmts = new ArrayList<>();
            for (JsonNode ver : pol.path("PolicyVersionList")) {
                if (ver.path("IsDefaultVersion").asBoolean(false) || ver.path("VersionId").asText().equals("v1")) {
                    stmts.addAll(parseStatements(ver.path("Document")));
                    break;
                }
            }
            if (stmts.isEmpty() && pol.has("PolicyVersionList") && pol.path("PolicyVersionList").size() > 0) {
                stmts.addAll(parseStatements(pol.path("PolicyVersionList").get(0).path("Document")));
            }
            if (!arn.isEmpty()) managedPolicyStatements.put(arn, stmts);
            if (!polName.isEmpty()) managedPolicyStatements.put(polName, stmts);
        }

        Map<String, ParsedRole> roles = new LinkedHashMap<>();
        Map<String, ParsedResource> resources = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();

        for (JsonNode rNode : root.path("RoleDetailList")) {
            String roleName = rNode.path("RoleName").asText("");
            String arn = rNode.path("Arn").asText("");
            if (roleName.isEmpty() && !arn.isEmpty()) {
                roleName = arn.substring(arn.lastIndexOf('/') + 1);
            }
            if (roleName.isEmpty()) continue;

            JsonNode trustDoc = rNode.path("AssumeRolePolicyDocument");
            OidcTrustInfo oidcTrust = parseOidcTrust(trustDoc);
            Set<String> trustedRoleArns = parseTrustedRoles(trustDoc);

            List<PolicyStatement> allStatements = new ArrayList<>();
            // Inline policies
            for (JsonNode inline : rNode.path("RolePolicyList")) {
                allStatements.addAll(parseStatements(inline.path("PolicyDocument")));
            }

            // Attached managed policies
            Set<String> attached = new LinkedHashSet<>();
            boolean isAdmin = false;
            for (JsonNode att : rNode.path("AttachedManagedPolicies")) {
                String pArn = att.path("PolicyArn").asText("");
                String pName = att.path("PolicyName").asText("");
                if (!pName.isEmpty()) attached.add(pName);
                if (!pArn.isEmpty()) attached.add(pArn);

                if ("AdministratorAccess".equalsIgnoreCase(pName) || pArn.endsWith("/AdministratorAccess")) {
                    isAdmin = true;
                }
                if (managedPolicyStatements.containsKey(pArn)) {
                    allStatements.addAll(managedPolicyStatements.get(pArn));
                } else if (managedPolicyStatements.containsKey(pName)) {
                    allStatements.addAll(managedPolicyStatements.get(pName));
                }
            }

            // Detect admin permissions via statements
            if (!isAdmin) {
                for (PolicyStatement stmt : allStatements) {
                    if (stmt.isAllow()) {
                        boolean fullAction = stmt.actions.contains("*") || stmt.actions.contains("*:*");
                        boolean fullResource = stmt.resources.contains("*");
                        if (fullAction && fullResource) {
                            isAdmin = true;
                            break;
                        }
                    }
                }
            }

            // Extract resources mentioned in statements
            for (PolicyStatement stmt : allStatements) {
                for (String resArn : stmt.resources) {
                    if (resArn.equals("*")) continue;
                    ParsedResource pr = parseResourceArn(resArn);
                    if (pr != null) {
                        resources.putIfAbsent(pr.name(), pr);
                    }
                }
            }

            ParsedRole role = new ParsedRole(roleName, arn, isAdmin, oidcTrust, allStatements, attached, trustedRoleArns);
            roles.put(roleName, role);
            if (!arn.isEmpty()) {
                roles.put(arn, role);
            }
        }

        return new IamParseResult(roles, resources, warnings);
    }

    private List<PolicyStatement> parseStatements(JsonNode doc) {
        List<PolicyStatement> list = new ArrayList<>();
        if (doc == null || doc.isMissingNode() || doc.isNull()) return list;

        JsonNode stmtNode = doc.path("Statement");
        List<JsonNode> rawStmts = new ArrayList<>();
        if (stmtNode.isArray()) {
            stmtNode.forEach(rawStmts::add);
        } else if (stmtNode.isObject()) {
            rawStmts.add(stmtNode);
        }

        for (JsonNode s : rawStmts) {
            String effect = s.path("Effect").asText("Allow");
            Set<String> actions = asStringSet(s.get("Action"));
            Set<String> notActions = asStringSet(s.get("NotAction"));
            Set<String> resources = asStringSet(s.get("Resource"));
            Set<String> notResources = asStringSet(s.get("NotResource"));

            Map<String, Map<String, List<String>>> conditions = new LinkedHashMap<>();
            JsonNode condNode = s.path("Condition");
            if (condNode.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> it = condNode.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> op = it.next();
                    String operator = op.getKey();
                    Map<String, List<String>> keyMap = new LinkedHashMap<>();
                    if (op.getValue().isObject()) {
                        Iterator<Map.Entry<String, JsonNode>> kit = op.getValue().fields();
                        while (kit.hasNext()) {
                            Map.Entry<String, JsonNode> keyEntry = kit.next();
                            List<String> vals = new ArrayList<>();
                            if (keyEntry.getValue().isArray()) {
                                keyEntry.getValue().forEach(v -> vals.add(v.asText()));
                            } else {
                                vals.add(keyEntry.getValue().asText());
                            }
                            keyMap.put(keyEntry.getKey(), vals);
                        }
                    }
                    conditions.put(operator, keyMap);
                }
            }

            list.add(new PolicyStatement(effect, actions, notActions, resources, notResources, conditions));
        }
        return list;
    }

    private Set<String> asStringSet(JsonNode node) {
        Set<String> set = new LinkedHashSet<>();
        if (node == null || node.isMissingNode() || node.isNull()) {
            return set;
        }
        if (node.isTextual()) {
            set.add(node.asText());
        } else if (node.isArray()) {
            node.forEach(n -> set.add(n.asText()));
        }
        return set;
    }

    private OidcTrustInfo parseOidcTrust(JsonNode trustDoc) {
        if (trustDoc == null || trustDoc.isMissingNode() || trustDoc.isNull()) {
            return new OidcTrustInfo(false, "", List.of(), false, false, null);
        }
        List<PolicyStatement> statements = parseStatements(trustDoc);
        boolean trustsGithub = false;
        String audience = "";
        List<String> subPatterns = new ArrayList<>();
        boolean missingSub = true;
        boolean overPermissive = false;
        String overPermissiveReason = null;

        for (PolicyStatement stmt : statements) {
            if (!stmt.isAllow()) continue;
            boolean hasOidcAction = stmt.actions.isEmpty() || stmt.actions.stream().anyMatch(a -> glob(a, "sts:AssumeRoleWithWebIdentity") || a.equals("*"));
            if (!hasOidcAction) continue;

            for (Map.Entry<String, Map<String, List<String>>> opEntry : stmt.conditions.entrySet()) {
                String operator = opEntry.getKey();
                Map<String, List<String>> kv = opEntry.getValue();
                for (Map.Entry<String, List<String>> e : kv.entrySet()) {
                    String k = e.getKey();
                    if (k.endsWith(":aud")) {
                        trustsGithub = true;
                        if (!e.getValue().isEmpty()) audience = e.getValue().get(0);
                    }
                    if (k.endsWith(":sub")) {
                        trustsGithub = true;
                        missingSub = false;
                        subPatterns.addAll(e.getValue());
                    }
                }
            }
        }

        if (trustsGithub) {
            if (missingSub) {
                overPermissive = true;
                overPermissiveReason = "Missing 'sub' condition in GitHub OIDC trust policy (allows any GitHub repository)";
            } else {
                for (String pat : subPatterns) {
                    if (pat.equals("*") || pat.equals("repo:*") || pat.startsWith("repo:*") || pat.matches("repo:[^/]+/\\*.*")) {
                        overPermissive = true;
                        overPermissiveReason = "Over-broad GitHub OIDC trust: wildcard repository pattern '" + pat + "'";
                        break;
                    }
                    if (pat.endsWith(":*") && !pat.contains(":ref:") && !pat.contains(":pull_request") && !pat.contains(":environment:")) {
                        overPermissive = true;
                        overPermissiveReason = "Over-broad GitHub OIDC trust: no branch or pull request restriction on repository";
                        break;
                    }
                }
            }
        }

        return new OidcTrustInfo(trustsGithub, audience, subPatterns, missingSub && trustsGithub, overPermissive, overPermissiveReason);
    }

    private Set<String> parseTrustedRoles(JsonNode trustDoc) {
        Set<String> roles = new LinkedHashSet<>();
        if (trustDoc == null || trustDoc.isMissingNode() || trustDoc.isNull()) return roles;
        List<PolicyStatement> statements = parseStatements(trustDoc);
        for (PolicyStatement s : statements) {
            if (s.isAllow() && s.actions.stream().anyMatch(a -> glob(a, "sts:AssumeRole") || a.equals("*"))) {
                // Check Principal
                // In AWS IAM, Principal can be {"AWS": "arn:aws:iam::..."}
                JsonNode stNode = trustDoc.path("Statement");
                if (stNode.isArray()) {
                    for (JsonNode sn : stNode) {
                        JsonNode p = sn.path("Principal").path("AWS");
                        if (p.isTextual()) roles.add(p.asText());
                        else if (p.isArray()) p.forEach(x -> roles.add(x.asText()));
                    }
                } else if (stNode.isObject()) {
                    JsonNode p = stNode.path("Principal").path("AWS");
                    if (p.isTextual()) roles.add(p.asText());
                    else if (p.isArray()) p.forEach(x -> roles.add(x.asText()));
                }
            }
        }
        return roles;
    }

    public ParsedResource parseResourceArn(String arn) {
        if (arn == null || arn.isBlank() || arn.equals("*")) return null;
        String raw = arn.trim();
        if (raw.endsWith("/*")) {
            raw = raw.substring(0, raw.length() - 2);
        }
        if (raw.endsWith("*") && raw.length() > 1 && !raw.endsWith("/*")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        if (raw.isEmpty() || raw.equals("*")) return null;

        String name = raw;
        String type = "unknown";

        if (raw.startsWith("arn:aws:")) {
            String[] parts = raw.split(":", 6);
            if (parts.length >= 6) {
                String service = parts[2];
                String rest = parts[5];
                type = service;
                if ("s3".equalsIgnoreCase(service)) {
                    // In S3: arn:aws:s3:::bucket-name/... -> bucket-name
                    if (rest.contains("/")) {
                        name = rest.substring(0, rest.indexOf('/'));
                    } else {
                        name = rest;
                    }
                } else if (rest.contains("/")) {
                    name = rest.substring(rest.lastIndexOf('/') + 1);
                } else if (rest.contains(":")) {
                    name = rest.substring(rest.lastIndexOf(':') + 1);
                } else {
                    name = rest;
                }
            }
        } else if (raw.contains("/")) {
            name = raw.substring(raw.lastIndexOf('/') + 1);
        }

        if (name.isEmpty() || name.equals("*")) {
            return null;
        }

        String lower = name.toLowerCase(Locale.ROOT);
        boolean sensitive = SENSITIVE_KEYWORDS.stream().anyMatch(lower::contains)
                || type.equalsIgnoreCase("rds") || type.equalsIgnoreCase("dynamodb") || type.equalsIgnoreCase("secretsmanager");

        return new ParsedResource(name, raw, type, sensitive, "");
    }

    public boolean matchesOidc(OidcTrustInfo trust, String repo, Set<String> triggers, String branch) {
        if (!trust.trustsGithub()) {
            return true;
        }
        if (trust.subPatterns().isEmpty()) {
            return trust.missingSub();
        }

        for (String event : triggers) {
            String subCandidate;
            if (event.equals("pull_request") || event.equals("pull_request_target")) {
                subCandidate = "repo:" + repo + ":pull_request";
            } else if (branch != null && !branch.isBlank()) {
                subCandidate = "repo:" + repo + ":ref:refs/heads/" + branch;
            } else {
                subCandidate = "repo:" + repo + ":ref:refs/heads/main";
            }

            for (String pattern : trust.subPatterns()) {
                if (glob(pattern, subCandidate) || glob(pattern, "repo:" + repo + ":*")) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean checkPermission(List<PolicyStatement> statements, String action, String resource) {
        boolean allowed = false;
        for (PolicyStatement stmt : statements) {
            if (statementMatches(stmt, action, resource)) {
                if (stmt.isDeny()) {
                    return false; // Deny overrides allow immediately
                }
                if (stmt.isAllow()) {
                    allowed = true;
                }
            }
        }
        return allowed;
    }

    public boolean canCreateCompute(List<PolicyStatement> statements) {
        for (String computeAction : COMPUTE_ACTIONS) {
            if (checkPermission(statements, computeAction, "*")) {
                return true;
            }
        }
        return false;
    }

    private boolean statementMatches(PolicyStatement stmt, String action, String resource) {
        boolean actionMatch;
        if (!stmt.actions.isEmpty()) {
            actionMatch = stmt.actions.stream().anyMatch(a -> glob(a, action));
        } else if (!stmt.notActions.isEmpty()) {
            actionMatch = stmt.notActions.stream().noneMatch(a -> glob(a, action));
        } else {
            actionMatch = false;
        }
        if (!actionMatch) return false;

        boolean resourceMatch;
        if (!stmt.resources.isEmpty()) {
            resourceMatch = stmt.resources.stream().anyMatch(r -> glob(r, resource) || glob(r, "*") || r.equals("*"));
        } else if (!stmt.notResources.isEmpty()) {
            resourceMatch = stmt.notResources.stream().noneMatch(r -> glob(r, resource));
        } else {
            resourceMatch = false;
        }
        return resourceMatch;
    }

    public static boolean glob(String pattern, String text) {
        if (pattern == null || text == null) return false;
        if (pattern.equals("*")) return true;
        String regex = Arrays.stream(pattern.split("\\*", -1)).map(Pattern::quote).collect(Collectors.joining(".*"));
        return Pattern.compile("^" + regex + "$", Pattern.CASE_INSENSITIVE).matcher(text).matches();
    }
}
