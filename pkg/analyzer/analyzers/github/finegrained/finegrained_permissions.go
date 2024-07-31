// Code generated by go generate; DO NOT EDIT.
package finegrained

import "errors"

type Permission int

const (
    NoAccess Permission = iota
    ActionsRead Permission = iota
    ActionsWrite Permission = iota
    AdministrationRead Permission = iota
    AdministrationWrite Permission = iota
    CodeScanningAlertsRead Permission = iota
    CodeScanningAlertsWrite Permission = iota
    CodespacesRead Permission = iota
    CodespacesWrite Permission = iota
    CodespacesLifecycleRead Permission = iota
    CodespacesLifecycleWrite Permission = iota
    CodespacesMetadataRead Permission = iota
    CodespacesMetadataWrite Permission = iota
    CodespacesSecretsRead Permission = iota
    CodespacesSecretsWrite Permission = iota
    CommitStatusesRead Permission = iota
    CommitStatusesWrite Permission = iota
    ContentsRead Permission = iota
    ContentsWrite Permission = iota
    CustomPropertiesRead Permission = iota
    CustomPropertiesWrite Permission = iota
    DependabotAlertsRead Permission = iota
    DependabotAlertsWrite Permission = iota
    DependabotSecretsRead Permission = iota
    DependabotSecretsWrite Permission = iota
    DeploymentsRead Permission = iota
    DeploymentsWrite Permission = iota
    EnvironmentsRead Permission = iota
    EnvironmentsWrite Permission = iota
    IssuesRead Permission = iota
    IssuesWrite Permission = iota
    MergeQueuesRead Permission = iota
    MergeQueuesWrite Permission = iota
    MetadataRead Permission = iota
    MetadataWrite Permission = iota
    PagesRead Permission = iota
    PagesWrite Permission = iota
    PullRequestsRead Permission = iota
    PullRequestsWrite Permission = iota
    RepoSecurityRead Permission = iota
    RepoSecurityWrite Permission = iota
    SecretScanningRead Permission = iota
    SecretScanningWrite Permission = iota
    SecretsRead Permission = iota
    SecretsWrite Permission = iota
    VariablesRead Permission = iota
    VariablesWrite Permission = iota
    WebhooksRead Permission = iota
    WebhooksWrite Permission = iota
    WorkflowsRead Permission = iota
    WorkflowsWrite Permission = iota
    BlockUserRead Permission = iota
    BlockUserWrite Permission = iota
    CodespaceUserSecretsRead Permission = iota
    CodespaceUserSecretsWrite Permission = iota
    EmailRead Permission = iota
    EmailWrite Permission = iota
    FollowersRead Permission = iota
    FollowersWrite Permission = iota
    GpgKeysRead Permission = iota
    GpgKeysWrite Permission = iota
    GistsRead Permission = iota
    GistsWrite Permission = iota
    GitKeysRead Permission = iota
    GitKeysWrite Permission = iota
    LimitsRead Permission = iota
    LimitsWrite Permission = iota
    PlanRead Permission = iota
    PlanWrite Permission = iota
    PrivateInvitesRead Permission = iota
    PrivateInvitesWrite Permission = iota
    ProfileRead Permission = iota
    ProfileWrite Permission = iota
    SigningKeysRead Permission = iota
    SigningKeysWrite Permission = iota
    StarringRead Permission = iota
    StarringWrite Permission = iota
    WatchingRead Permission = iota
    WatchingWrite Permission = iota
)

var (
    PermissionStrings = map[Permission]string{
        ActionsRead: "actions:read",
        ActionsWrite: "actions:write",
        AdministrationRead: "administration:read",
        AdministrationWrite: "administration:write",
        CodeScanningAlertsRead: "code_scanning_alerts:read",
        CodeScanningAlertsWrite: "code_scanning_alerts:write",
        CodespacesRead: "codespaces:read",
        CodespacesWrite: "codespaces:write",
        CodespacesLifecycleRead: "codespaces_lifecycle:read",
        CodespacesLifecycleWrite: "codespaces_lifecycle:write",
        CodespacesMetadataRead: "codespaces_metadata:read",
        CodespacesMetadataWrite: "codespaces_metadata:write",
        CodespacesSecretsRead: "codespaces_secrets:read",
        CodespacesSecretsWrite: "codespaces_secrets:write",
        CommitStatusesRead: "commit_statuses:read",
        CommitStatusesWrite: "commit_statuses:write",
        ContentsRead: "contents:read",
        ContentsWrite: "contents:write",
        CustomPropertiesRead: "custom_properties:read",
        CustomPropertiesWrite: "custom_properties:write",
        DependabotAlertsRead: "dependabot_alerts:read",
        DependabotAlertsWrite: "dependabot_alerts:write",
        DependabotSecretsRead: "dependabot_secrets:read",
        DependabotSecretsWrite: "dependabot_secrets:write",
        DeploymentsRead: "deployments:read",
        DeploymentsWrite: "deployments:write",
        EnvironmentsRead: "environments:read",
        EnvironmentsWrite: "environments:write",
        IssuesRead: "issues:read",
        IssuesWrite: "issues:write",
        MergeQueuesRead: "merge_queues:read",
        MergeQueuesWrite: "merge_queues:write",
        MetadataRead: "metadata:read",
        MetadataWrite: "metadata:write",
        PagesRead: "pages:read",
        PagesWrite: "pages:write",
        PullRequestsRead: "pull_requests:read",
        PullRequestsWrite: "pull_requests:write",
        RepoSecurityRead: "repo_security:read",
        RepoSecurityWrite: "repo_security:write",
        SecretScanningRead: "secret_scanning:read",
        SecretScanningWrite: "secret_scanning:write",
        SecretsRead: "secrets:read",
        SecretsWrite: "secrets:write",
        VariablesRead: "variables:read",
        VariablesWrite: "variables:write",
        WebhooksRead: "webhooks:read",
        WebhooksWrite: "webhooks:write",
        WorkflowsRead: "workflows:read",
        WorkflowsWrite: "workflows:write",
        BlockUserRead: "block_user:read",
        BlockUserWrite: "block_user:write",
        CodespaceUserSecretsRead: "codespace_user_secrets:read",
        CodespaceUserSecretsWrite: "codespace_user_secrets:write",
        EmailRead: "email:read",
        EmailWrite: "email:write",
        FollowersRead: "followers:read",
        FollowersWrite: "followers:write",
        GpgKeysRead: "gpg_keys:read",
        GpgKeysWrite: "gpg_keys:write",
        GistsRead: "gists:read",
        GistsWrite: "gists:write",
        GitKeysRead: "git_keys:read",
        GitKeysWrite: "git_keys:write",
        LimitsRead: "limits:read",
        LimitsWrite: "limits:write",
        PlanRead: "plan:read",
        PlanWrite: "plan:write",
        PrivateInvitesRead: "private_invites:read",
        PrivateInvitesWrite: "private_invites:write",
        ProfileRead: "profile:read",
        ProfileWrite: "profile:write",
        SigningKeysRead: "signing_keys:read",
        SigningKeysWrite: "signing_keys:write",
        StarringRead: "starring:read",
        StarringWrite: "starring:write",
        WatchingRead: "watching:read",
        WatchingWrite: "watching:write",
    }

    StringToPermission = map[string]Permission{
        "actions:read": ActionsRead,
        "actions:write": ActionsWrite,
        "administration:read": AdministrationRead,
        "administration:write": AdministrationWrite,
        "code_scanning_alerts:read": CodeScanningAlertsRead,
        "code_scanning_alerts:write": CodeScanningAlertsWrite,
        "codespaces:read": CodespacesRead,
        "codespaces:write": CodespacesWrite,
        "codespaces_lifecycle:read": CodespacesLifecycleRead,
        "codespaces_lifecycle:write": CodespacesLifecycleWrite,
        "codespaces_metadata:read": CodespacesMetadataRead,
        "codespaces_metadata:write": CodespacesMetadataWrite,
        "codespaces_secrets:read": CodespacesSecretsRead,
        "codespaces_secrets:write": CodespacesSecretsWrite,
        "commit_statuses:read": CommitStatusesRead,
        "commit_statuses:write": CommitStatusesWrite,
        "contents:read": ContentsRead,
        "contents:write": ContentsWrite,
        "custom_properties:read": CustomPropertiesRead,
        "custom_properties:write": CustomPropertiesWrite,
        "dependabot_alerts:read": DependabotAlertsRead,
        "dependabot_alerts:write": DependabotAlertsWrite,
        "dependabot_secrets:read": DependabotSecretsRead,
        "dependabot_secrets:write": DependabotSecretsWrite,
        "deployments:read": DeploymentsRead,
        "deployments:write": DeploymentsWrite,
        "environments:read": EnvironmentsRead,
        "environments:write": EnvironmentsWrite,
        "issues:read": IssuesRead,
        "issues:write": IssuesWrite,
        "merge_queues:read": MergeQueuesRead,
        "merge_queues:write": MergeQueuesWrite,
        "metadata:read": MetadataRead,
        "metadata:write": MetadataWrite,
        "pages:read": PagesRead,
        "pages:write": PagesWrite,
        "pull_requests:read": PullRequestsRead,
        "pull_requests:write": PullRequestsWrite,
        "repo_security:read": RepoSecurityRead,
        "repo_security:write": RepoSecurityWrite,
        "secret_scanning:read": SecretScanningRead,
        "secret_scanning:write": SecretScanningWrite,
        "secrets:read": SecretsRead,
        "secrets:write": SecretsWrite,
        "variables:read": VariablesRead,
        "variables:write": VariablesWrite,
        "webhooks:read": WebhooksRead,
        "webhooks:write": WebhooksWrite,
        "workflows:read": WorkflowsRead,
        "workflows:write": WorkflowsWrite,
        "block_user:read": BlockUserRead,
        "block_user:write": BlockUserWrite,
        "codespace_user_secrets:read": CodespaceUserSecretsRead,
        "codespace_user_secrets:write": CodespaceUserSecretsWrite,
        "email:read": EmailRead,
        "email:write": EmailWrite,
        "followers:read": FollowersRead,
        "followers:write": FollowersWrite,
        "gpg_keys:read": GpgKeysRead,
        "gpg_keys:write": GpgKeysWrite,
        "gists:read": GistsRead,
        "gists:write": GistsWrite,
        "git_keys:read": GitKeysRead,
        "git_keys:write": GitKeysWrite,
        "limits:read": LimitsRead,
        "limits:write": LimitsWrite,
        "plan:read": PlanRead,
        "plan:write": PlanWrite,
        "private_invites:read": PrivateInvitesRead,
        "private_invites:write": PrivateInvitesWrite,
        "profile:read": ProfileRead,
        "profile:write": ProfileWrite,
        "signing_keys:read": SigningKeysRead,
        "signing_keys:write": SigningKeysWrite,
        "starring:read": StarringRead,
        "starring:write": StarringWrite,
        "watching:read": WatchingRead,
        "watching:write": WatchingWrite,
    }

    PermissionIDs = map[Permission]int{
        ActionsRead: 0,
        ActionsWrite: 1,
        AdministrationRead: 2,
        AdministrationWrite: 3,
        CodeScanningAlertsRead: 4,
        CodeScanningAlertsWrite: 5,
        CodespacesRead: 6,
        CodespacesWrite: 7,
        CodespacesLifecycleRead: 8,
        CodespacesLifecycleWrite: 9,
        CodespacesMetadataRead: 10,
        CodespacesMetadataWrite: 11,
        CodespacesSecretsRead: 12,
        CodespacesSecretsWrite: 13,
        CommitStatusesRead: 14,
        CommitStatusesWrite: 15,
        ContentsRead: 16,
        ContentsWrite: 17,
        CustomPropertiesRead: 18,
        CustomPropertiesWrite: 19,
        DependabotAlertsRead: 20,
        DependabotAlertsWrite: 21,
        DependabotSecretsRead: 22,
        DependabotSecretsWrite: 23,
        DeploymentsRead: 24,
        DeploymentsWrite: 25,
        EnvironmentsRead: 26,
        EnvironmentsWrite: 27,
        IssuesRead: 28,
        IssuesWrite: 29,
        MergeQueuesRead: 30,
        MergeQueuesWrite: 31,
        MetadataRead: 32,
        MetadataWrite: 33,
        PagesRead: 34,
        PagesWrite: 35,
        PullRequestsRead: 36,
        PullRequestsWrite: 37,
        RepoSecurityRead: 38,
        RepoSecurityWrite: 39,
        SecretScanningRead: 40,
        SecretScanningWrite: 41,
        SecretsRead: 42,
        SecretsWrite: 43,
        VariablesRead: 44,
        VariablesWrite: 45,
        WebhooksRead: 46,
        WebhooksWrite: 47,
        WorkflowsRead: 48,
        WorkflowsWrite: 49,
        BlockUserRead: 50,
        BlockUserWrite: 51,
        CodespaceUserSecretsRead: 52,
        CodespaceUserSecretsWrite: 53,
        EmailRead: 54,
        EmailWrite: 55,
        FollowersRead: 56,
        FollowersWrite: 57,
        GpgKeysRead: 58,
        GpgKeysWrite: 59,
        GistsRead: 60,
        GistsWrite: 61,
        GitKeysRead: 62,
        GitKeysWrite: 63,
        LimitsRead: 64,
        LimitsWrite: 65,
        PlanRead: 66,
        PlanWrite: 67,
        PrivateInvitesRead: 68,
        PrivateInvitesWrite: 69,
        ProfileRead: 70,
        ProfileWrite: 71,
        SigningKeysRead: 72,
        SigningKeysWrite: 73,
        StarringRead: 74,
        StarringWrite: 75,
        WatchingRead: 76,
        WatchingWrite: 77,
    }

    IdToPermission = map[int]Permission{
        0: ActionsRead,
        1: ActionsWrite,
        2: AdministrationRead,
        3: AdministrationWrite,
        4: CodeScanningAlertsRead,
        5: CodeScanningAlertsWrite,
        6: CodespacesRead,
        7: CodespacesWrite,
        8: CodespacesLifecycleRead,
        9: CodespacesLifecycleWrite,
        10: CodespacesMetadataRead,
        11: CodespacesMetadataWrite,
        12: CodespacesSecretsRead,
        13: CodespacesSecretsWrite,
        14: CommitStatusesRead,
        15: CommitStatusesWrite,
        16: ContentsRead,
        17: ContentsWrite,
        18: CustomPropertiesRead,
        19: CustomPropertiesWrite,
        20: DependabotAlertsRead,
        21: DependabotAlertsWrite,
        22: DependabotSecretsRead,
        23: DependabotSecretsWrite,
        24: DeploymentsRead,
        25: DeploymentsWrite,
        26: EnvironmentsRead,
        27: EnvironmentsWrite,
        28: IssuesRead,
        29: IssuesWrite,
        30: MergeQueuesRead,
        31: MergeQueuesWrite,
        32: MetadataRead,
        33: MetadataWrite,
        34: PagesRead,
        35: PagesWrite,
        36: PullRequestsRead,
        37: PullRequestsWrite,
        38: RepoSecurityRead,
        39: RepoSecurityWrite,
        40: SecretScanningRead,
        41: SecretScanningWrite,
        42: SecretsRead,
        43: SecretsWrite,
        44: VariablesRead,
        45: VariablesWrite,
        46: WebhooksRead,
        47: WebhooksWrite,
        48: WorkflowsRead,
        49: WorkflowsWrite,
        50: BlockUserRead,
        51: BlockUserWrite,
        52: CodespaceUserSecretsRead,
        53: CodespaceUserSecretsWrite,
        54: EmailRead,
        55: EmailWrite,
        56: FollowersRead,
        57: FollowersWrite,
        58: GpgKeysRead,
        59: GpgKeysWrite,
        60: GistsRead,
        61: GistsWrite,
        62: GitKeysRead,
        63: GitKeysWrite,
        64: LimitsRead,
        65: LimitsWrite,
        66: PlanRead,
        67: PlanWrite,
        68: PrivateInvitesRead,
        69: PrivateInvitesWrite,
        70: ProfileRead,
        71: ProfileWrite,
        72: SigningKeysRead,
        73: SigningKeysWrite,
        74: StarringRead,
        75: StarringWrite,
        76: WatchingRead,
        77: WatchingWrite,
    }
)

// ToString converts a Permission enum to its string representation
func (p Permission) ToString() (string, error) {
    if str, ok := PermissionStrings[p]; ok {
        return str, nil
    }
    return "", errors.New("invalid permission")
}

// ToID converts a Permission enum to its ID
func (p Permission) ToID() (int, error) {
    if id, ok := PermissionIDs[p]; ok {
        return id, nil
    }
    return 0, errors.New("invalid permission")
}

// PermissionFromString converts a string representation to its Permission enum
func PermissionFromString(s string) (Permission, error) {
    if p, ok := StringToPermission[s]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission string")
}

// PermissionFromID converts an ID to its Permission enum
func PermissionFromID(id int) (Permission, error) {
    if p, ok := IdToPermission[id]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission ID")
}
