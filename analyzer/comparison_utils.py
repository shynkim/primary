def compare_apk_and_policy(apk_result, policy_result):
    try:
        perms = apk_result.get("permissions", []) or []
        # policy_result may contain ml -> mentioned_permissions or basic flags
        mentioned = []
        if isinstance(policy_result, dict):
            if 'ml' in policy_result and isinstance(policy_result['ml'], dict):
                mentioned = policy_result['ml'].get('mentioned_permissions', []) or []
            else:
                # legacy keys
                mentioned = []
                if policy_result.get('contains_location'):
                    mentioned += [p for p in perms if 'LOCATION' in p]
                if policy_result.get('contains_camera'):
                    mentioned += [p for p in perms if 'CAMERA' in p]
                if policy_result.get('contains_contact'):
                    mentioned += [p for p in perms if 'CONTACT' in p]

        mentioned_set = set(mentioned)
        unmentioned = [p for p in perms if p not in mentioned_set]

        return {
            "mentioned_permissions": list(mentioned_set),
            "unmentioned_permissions": unmentioned,
            "count_unmentioned": len(unmentioned),
            "count_mentioned": len(mentioned_set)
        }
    except Exception as e:
        return {"error": str(e)}
