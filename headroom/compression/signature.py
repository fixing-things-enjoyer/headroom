"""Structural signatures for compressed payloads."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolSignature:
    """Signature of an output structure used for local cache correlation."""

    # Structural hash (based on field types and names)
    # MEDIUM FIX #15: Uses SHA256[:24] (96 bits) for better collision resistance
    structure_hash: str  # SHA256[:24] of sorted field names + types

    # Schema characteristics
    field_count: int
    has_nested_objects: bool
    has_arrays: bool
    max_depth: int

    # Field type distribution
    string_field_count: int = 0
    numeric_field_count: int = 0
    boolean_field_count: int = 0
    array_field_count: int = 0
    object_field_count: int = 0

    # Pattern indicators (without revealing actual field names)
    has_id_like_field: bool = False
    has_score_like_field: bool = False
    has_timestamp_like_field: bool = False
    has_status_like_field: bool = False
    has_error_like_field: bool = False
    has_message_like_field: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "structure_hash": self.structure_hash,
            "field_count": self.field_count,
            "has_nested_objects": self.has_nested_objects,
            "has_arrays": self.has_arrays,
            "max_depth": self.max_depth,
            "string_field_count": self.string_field_count,
            "numeric_field_count": self.numeric_field_count,
            "boolean_field_count": self.boolean_field_count,
            "array_field_count": self.array_field_count,
            "object_field_count": self.object_field_count,
            "has_id_like_field": self.has_id_like_field,
            "has_score_like_field": self.has_score_like_field,
            "has_timestamp_like_field": self.has_timestamp_like_field,
            "has_status_like_field": self.has_status_like_field,
            "has_error_like_field": self.has_error_like_field,
            "has_message_like_field": self.has_message_like_field,
        }

    @staticmethod
    def _calculate_depth(value: Any, current_depth: int = 1, max_depth_limit: int = 10) -> int:
        """Recursively calculate the depth of a nested structure.

        MEDIUM FIX #12: Actually calculate max_depth instead of hardcoding 1.
        """
        if current_depth >= max_depth_limit:
            return current_depth  # Prevent infinite recursion

        if isinstance(value, dict):
            if not value:
                return current_depth
            return max(
                ToolSignature._calculate_depth(v, current_depth + 1, max_depth_limit)
                for v in value.values()
            )
        elif isinstance(value, list):
            if not value:
                return current_depth
            # Sample first few items in arrays to avoid O(n) traversal
            sample_items = value[:3]
            return max(
                ToolSignature._calculate_depth(item, current_depth + 1, max_depth_limit)
                for item in sample_items
            )
        else:
            return current_depth

    @staticmethod
    def _matches_pattern(
        key_lower: str, patterns: list[str], original_key: str | None = None
    ) -> bool:
        """Check if key matches patterns using word boundary matching.

        MEDIUM FIX #14: Prevent false positives like "hidden" matching "id".
        Uses word boundary logic: pattern must be at start/end or surrounded by
        non-alphanumeric characters (underscore, hyphen, or boundary).

        Args:
            key_lower: The field name in lowercase
            patterns: List of patterns to match against
            original_key: The original field name (for camelCase detection)
        """
        import re

        for pattern in patterns:
            # Exact match
            if key_lower == pattern:
                return True

            # Pattern at start with delimiter: "id_something" or "id-something"
            if key_lower.startswith(pattern + "_") or key_lower.startswith(pattern + "-"):
                return True

            # Pattern at end with delimiter: "user_id" or "user-id"
            if key_lower.endswith("_" + pattern) or key_lower.endswith("-" + pattern):
                return True

            # Pattern in middle with delimiters: "some_id_field"
            if f"_{pattern}_" in key_lower or f"-{pattern}-" in key_lower:
                return True
            if f"_{pattern}-" in key_lower or f"-{pattern}_" in key_lower:
                return True

            # camelCase detection: Look for capitalized pattern in original key
            # e.g., "userId" should match "id" (as "Id")
            if original_key:
                # Pattern capitalized (e.g., "Id" for "id")
                cap_pattern = pattern.capitalize()
                # Look for capital letter at start of pattern, preceded by lowercase
                camel_regex = rf"(?<=[a-z]){re.escape(cap_pattern)}(?=[A-Z]|$)"
                if re.search(camel_regex, original_key):
                    return True

        return False

    @classmethod
    def from_items(cls, items: list[dict[str, Any]]) -> ToolSignature:
        """Create signature from sample items."""
        if not items:
            # HIGH FIX: Generate unique hash for empty outputs to prevent
            # different tools' empty responses from colliding into one pattern.
            # Use a random component to ensure uniqueness across tool types.
            import uuid

            # MEDIUM FIX #15: Use 24 chars (96 bits) instead of 16 (64 bits) to reduce collision risk
            empty_hash = hashlib.sha256(f"empty:{uuid.uuid4()}".encode()).hexdigest()[:24]
            return cls(
                structure_hash=empty_hash,
                field_count=0,
                has_nested_objects=False,
                has_arrays=False,
                max_depth=0,
            )

        # MEDIUM FIX #13: Analyze multiple items (up to 5) to get representative structure
        # This catches cases where items have varying schemas
        sample_items = items[:5] if len(items) >= 5 else items

        # Merge field info from all sampled items
        all_fields: dict[str, set[str]] = {}  # field_name -> set of types seen
        for item in sample_items:
            if not isinstance(item, dict):
                continue
            for key, value in item.items():
                if key not in all_fields:
                    all_fields[key] = set()
                # Determine type
                if isinstance(value, str):
                    all_fields[key].add("string")
                elif isinstance(value, bool):
                    all_fields[key].add("boolean")
                elif isinstance(value, (int, float)):
                    all_fields[key].add("numeric")
                elif isinstance(value, list):
                    all_fields[key].add("array")
                elif isinstance(value, dict):
                    all_fields[key].add("object")
                else:
                    all_fields[key].add("null")

        # Build field_info with most common type per field
        field_info: list[tuple[str, str]] = []
        string_count = 0
        numeric_count = 0
        boolean_count = 0
        array_count = 0
        object_count = 0
        has_nested = False
        has_arrays = False

        # MEDIUM FIX #12: Calculate actual max_depth from sampled items
        max_depth = 1
        for item in sample_items:
            if isinstance(item, dict):
                item_depth = cls._calculate_depth(item)
                max_depth = max(max_depth, item_depth)

        # Pattern detection (heuristic field name matching)
        has_id = False
        has_score = False
        has_timestamp = False
        has_status = False
        has_error = False
        has_message = False

        for key, types in all_fields.items():
            key_lower = key.lower()

            # Use most specific type if multiple seen (prefer non-null)
            types_no_null = types - {"null"}
            if len(types_no_null) == 1:
                field_type = types_no_null.pop()
            elif len(types_no_null) > 1:
                # Multiple types seen - mark as mixed but pick one for counting
                # Priority: object > array > string > numeric > boolean
                for t in ["object", "array", "string", "numeric", "boolean"]:
                    if t in types_no_null:
                        field_type = t
                        break
                else:
                    field_type = "mixed"
            elif types:
                field_type = types.pop()  # Only null seen
            else:
                field_type = "null"

            # Count field types
            if field_type == "string":
                string_count += 1
            elif field_type == "boolean":
                boolean_count += 1
            elif field_type == "numeric":
                numeric_count += 1
            elif field_type == "array":
                array_count += 1
                has_arrays = True
            elif field_type == "object":
                object_count += 1
                has_nested = True

            field_info.append((key, field_type))

            # MEDIUM FIX #14: Pattern detection with word boundary matching
            # Prevents false positives like "hidden" matching "id"
            # Pass original key for camelCase detection
            if cls._matches_pattern(key_lower, ["id", "uuid", "guid"], key) or key_lower.endswith(
                "key"
            ):
                has_id = True
            if cls._matches_pattern(
                key_lower, ["score", "rank", "rating", "relevance", "priority"], key
            ):
                has_score = True
            if (
                cls._matches_pattern(key_lower, ["time", "date", "timestamp"], key)
                or key_lower.endswith("_at")
                or key_lower in ["created", "updated"]
            ):
                has_timestamp = True
            if cls._matches_pattern(key_lower, ["status", "state"], key) or key_lower in [
                "level",
                "type",
                "kind",
            ]:
                has_status = True
            if cls._matches_pattern(key_lower, ["error", "exception", "fail", "warning"], key):
                has_error = True
            if cls._matches_pattern(
                key_lower, ["message", "msg", "text", "content", "body", "description"], key
            ):
                has_message = True

        # Create structure hash
        # MEDIUM FIX #15: Use 24 chars (96 bits) instead of 16 (64 bits) for collision resistance
        sorted_fields = sorted(field_info)
        hash_input = json.dumps(sorted_fields, sort_keys=True)
        structure_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:24]

        return cls(
            structure_hash=structure_hash,
            field_count=len(field_info),
            has_nested_objects=has_nested,
            has_arrays=has_arrays,
            max_depth=max_depth,
            string_field_count=string_count,
            numeric_field_count=numeric_count,
            boolean_field_count=boolean_count,
            array_field_count=array_count,
            object_field_count=object_count,
            has_id_like_field=has_id,
            has_score_like_field=has_score,
            has_timestamp_like_field=has_timestamp,
            has_status_like_field=has_status,
            has_error_like_field=has_error,
            has_message_like_field=has_message,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolSignature:
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

