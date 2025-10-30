class PolicyAnalyzer:
    def __init__(self, policy_path):
        self.policy_path = policy_path

    def analyze(self):
        try:
            with open(self.policy_path, 'r', encoding='utf-8') as f:
                text = f.read()
            return {
                "contains_location": "위치" in text,
                "contains_camera": "카메라" in text,
                "contains_contact": "연락처" in text,
                "summary": text[:200] + "..." if len(text) > 200 else text,
                "status": "completed"
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}
