import logging
from typing import List, Optional, Union

from casbin import persist
from casbin.model import Model
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from .entities import Role, User
from .policy_loader_abc import PolicyLoaderABC

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class PolicyDbLoader(PolicyLoaderABC):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.Session = sessionmaker(bind=engine)
        self._subject = None

    def set_filtered(self, is_filtered: bool = True):
        self._is_filtered = is_filtered

    def is_filtered(self) -> bool:
        return getattr(self, "_is_filtered", False)

    def load_policy(self, model: Model,
                    entity: Optional[Union[User, Role]] = None,
                    filter: dict = None
                    ) -> None:
        """
        Load policy rules from database.
        If subject is provided, loads policies for that specific subject (User or Role).
        If no subject is provided (Casbin's default call), loads all policies.
        """
        if entity:
            # Get the actual class names for comparison
            # subject_class = entity.__class__.__name__
            # if subject_class == "User":
            if isinstance(entity, User):
                logger.debug(f"Loading policies for User: {entity.id}")
                query = self._get_user_policy_query()
                params = {"user_id": entity.id}

            # elif subject_class == "Role":
            elif isinstance(entity, Role):
                logger.debug(f"Loading policies for Role: {entity.role_name}")
                query = self._get_role_policy_query()
                params = {"role_id": entity.id}

            else:
                logger.warning(f"Unsupported subject type: {entity.__class__.__name__}")
                return

            # Execute query and load policies into Casbin model
            self._run_load_policy(query, params, model)
        elif filter:
            # assert "scope" in filter and "app_id" in filter, "Filter must include 'scope' and 'app_id'"
            # self._is_filtered = True
            query = self._get_filtered_policies_query()
            params = filter

            self._run_load_policy(query, params, model)
        else:
            # Casbin's default call - load all policies
            logger.debug("Loading all policies...")
            query = self._get_all_policies_query()
            self._run_load_policy(query, {}, model)

    def _run_load_policy(self, query: str, params: dict, model: Model) -> None:
        """
        Private method to execute the query and load policies into the Casbin model.
        """
        session = self.Session()
        try:
            result = session.execute(text(query), params)
            for row in result:
                if row.ptype == "p":  # Only add effect for permission policies
                    effect = row.effect if row.effect else "allow"  # Default to "allow" if missing
                    line = f"{row.ptype}, {row.subject}, {row.object}, {row.action}, {effect}"
                elif row.ptype == "g":
                    line = f"{row.ptype}, {row.subject}, {row.object}"
                else:
                    logger.warning(f"Unknown policy type: {row.ptype}")
                    continue
                logger.debug(f"Loading policy rule: {line}")
                persist.load_policy_line(line, model)
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
            logger.exception(e)  # This will print the full stack trace
        finally:
            session.close()

    def _get_filtered_policies_query(self) -> str:
        return """
        WITH role_permissions AS (
            SELECT DISTINCT
                'p' AS ptype,
                r.scope || ':' || COALESCE(r.app_id::text, '') || ':' || r.role_name AS subject,
                res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
                perm.action AS action,
                COALESCE(rp.effect, 'allow') AS effect
            FROM iam_role_policies rp
            JOIN iam_roles r ON rp.role_id = r.id
            JOIN iam_permissions perm ON rp.permission_id = perm.id
            JOIN iam_resources res ON perm.resource_id = res.id
            WHERE r.scope = :scope AND (:app_id IS NULL OR r.app_id = :app_id)
            AND res.scope = :scope AND (:app_id IS NULL OR res.app_id = :app_id)
        ),
        user_permissions AS (
            SELECT DISTINCT
                'p' AS ptype,
                u.id::text AS subject,
                res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
                perm.action AS action,
                COALESCE(up.effect, 'allow') AS effect
            FROM iam_user_policies up
            JOIN users u ON up.user_id = u.id
            JOIN iam_permissions perm ON up.permission_id = perm.id
            JOIN iam_resources res ON perm.resource_id = res.id
            WHERE res.scope = :scope AND (:app_id IS NULL OR res.app_id = :app_id)
        ),
        user_roles AS (
            SELECT DISTINCT
                'g' AS ptype,
                u.id::text AS subject,
                r.scope || ':' || COALESCE(r.app_id::text, '') || ':' || r.role_name AS object,
                NULL AS action,
                NULL AS effect
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            JOIN iam_roles r ON ur.role_id = r.id
            WHERE r.scope = :scope AND (:app_id IS NULL OR r.app_id = :app_id)
        )
        SELECT ptype, subject, object, action, effect FROM role_permissions
        UNION ALL
        SELECT ptype, subject, object, action, effect FROM user_permissions
        UNION ALL
        SELECT ptype, subject, object, action, effect FROM user_roles
        """

    def _get_all_policies_query(self) -> str:
        """Get query for loading all policies from the database."""
        return """
-- Load all policies: both "g" (user-to-role) and "p" (role-to-permission)
WITH role_permissions AS (
    -- Role-based policies
    SELECT DISTINCT
        'p' AS ptype,                                           -- Role-permission policy
        r.scope || ':' || COALESCE(r.app_id::text, '') || ':' || r.role_name AS subject,
        res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
        perm.action AS action,                                  -- Action (read, write, etc.)
        COALESCE(rp.effect, 'allow') AS effect                  -- Allow/Deny
    FROM iam_role_policies rp
    JOIN iam_roles r ON rp.role_id = r.id
    JOIN iam_permissions perm ON rp.permission_id = perm.id
    JOIN iam_resources res ON perm.resource_id = res.id
),
user_permissions AS (
    -- User-specific policies
    SELECT DISTINCT
        'p' AS ptype,                                           -- User-permission policy
        u.id::text AS subject,                                      -- User directly as subject
        res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
        perm.action AS action,                                  -- Action (read, write, etc.)
        COALESCE(up.effect, 'allow') AS effect                  -- Allow/Deny
    FROM iam_user_policies up
    JOIN users u ON up.user_id = u.id
    JOIN iam_permissions perm ON up.permission_id = perm.id
    JOIN iam_resources res ON perm.resource_id = res.id
),
user_roles AS (
    -- User-to-role mappings
    SELECT DISTINCT
        'g' AS ptype,                                           -- User-role mapping
        u.id::text AS subject,                                      -- User as subject
        r.scope || ':' || COALESCE(r.app_id::text, '') || ':' || r.role_name AS object,
        NULL AS action,                                         -- No action for "g" rules
        NULL AS effect                                          -- No effect for "g" rules
    FROM user_roles ur
    JOIN users u ON ur.user_id = u.id
    JOIN iam_roles r ON ur.role_id = r.id
)
-- Combine all policies: role, user, and group mappings
SELECT ptype, subject, object, action, effect FROM role_permissions
UNION ALL
SELECT ptype, subject, object, action, effect FROM user_permissions
UNION ALL
SELECT ptype, subject, object, action, effect FROM user_roles
        """

    def _get_role_policy_query(self) -> str:
        return """
WITH role_permissions AS (
    -- Get all permissions (allow/deny) for the specified role
    SELECT 
        'p' as ptype,                                           -- Casbin policy type: allow or deny
        r.role_name AS subject,                                 -- Role as Casbin subject
        CONCAT(res.scope, ':', res.resource_name) AS object,    -- Scoped resource
        perm.action AS action,                                   -- Action
        CASE
            WHEN rp.effect = 'deny' THEN 'deny'
            ELSE 'allow'
        END AS effect                    
    FROM iam_roles r
    JOIN iam_role_policies rp ON rp.role_id = r.id
    JOIN iam_permissions perm ON rp.permission_id = perm.id
    JOIN iam_resources res ON perm.resource_id = res.id
    WHERE r.id = :role_id
)
SELECT * FROM role_permissions;        
        """

    def _get_user_policy_query(self) -> str:
        return """
WITH user_roles AS (
    -- Get all roles assigned to the user
    SELECT 
        r.id AS role_id,
        r.scope || ':' || COALESCE(r.app_id::text, '') || ':' || r.role_name AS role_name
    FROM user_roles ur
    JOIN iam_roles r ON ur.role_id = r.id
    JOIN users u ON ur.user_id = u.id
    WHERE u.id = :user_id
),
role_permissions AS (
    -- Get all role-based permissions for the user
    SELECT 
        'p' AS ptype,                                           -- Casbin policy type: allow/deny
        ur.role_name AS subject,                                -- Role as the subject
        res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
        perm.action AS action,                                  -- Action
        COALESCE(rp.effect, 'allow') AS effect                  -- Allow/Deny
    FROM user_roles ur
    JOIN iam_role_policies rp ON ur.role_id = rp.role_id
    JOIN iam_permissions perm ON rp.permission_id = perm.id
    JOIN iam_resources res ON perm.resource_id = res.id
),
user_permissions AS (
    -- Get direct user-specific permissions
    SELECT 
        'p' AS ptype,                                           -- Casbin policy type: allow/deny
        u.id::text AS subject,                                      -- User as Casbin subject
        res.scope || ':' || COALESCE(res.app_id::text, '') || ':' || res.resource_name AS object,
        perm.action AS action,                                  -- Action
        COALESCE(up.effect, 'allow') AS effect                  -- Allow/Deny
    FROM iam_user_policies up
    JOIN users u ON up.user_id = u.id
    JOIN iam_permissions perm ON up.permission_id = perm.id
    JOIN iam_resources res ON perm.resource_id = res.id
    WHERE u.id = :user_id
),
user_roles_mappings AS (
    -- Map user to roles for Casbin "g" rules
    SELECT 
        'g' AS ptype,                                           -- Casbin group rule
        u.id::text AS subject,                                      -- User as Casbin subject
        ur.role_name AS object,                                 -- Role as Casbin object
        NULL AS action,                                         -- No action for "g" rules
        NULL AS effect                                          -- No effect for "g" rules
    FROM user_roles ur
    JOIN users u ON u.id = :user_id
)
-- Combine all policies into a single result set
SELECT ptype, subject, object, action, effect FROM role_permissions
UNION ALL
SELECT ptype, subject, object, action, effect FROM user_permissions
UNION ALL
SELECT ptype, subject, object, action, effect FROM user_roles_mappings;
        """

    def save_policy(self, model: Model) -> bool:
        """Save policy to database."""
        # This is now handled by the IAM service
        return True

    def add_policy(self, sec: str, ptype: str, rule: List[str]) -> bool:
        """Add policy rule to the storage."""
        # This is now handled by the IAM service
        return True

    def remove_policy(self, sec: str, ptype: str, rule: List[str]) -> bool:
        """Remove policy rule from the storage."""
        # This is now handled by the IAM service
        return True

    def remove_filtered_policy(self, sec: str, ptype: str, field_index: int, *field_values: str) -> bool:
        """Remove policy rules that match the filter from the storage."""
        # This is now handled by the IAM service
        return True
