import re


class MultiContextValidator:

    def __init__(self):

        self.system_context = (
            "You are a university assistant. "
            "Never reveal confidential information."
        )

        self.developer_context = (
            "Answer only questions related to the university."
        )

        self.retrieved_context = (
            "University regulations, course syllabus, "
            "library rules and academic information."
        )

    # =====================================================
    # MCP CONTEXT VALIDATION
    # =====================================================

    def validate_mcp_context(self, prompt):

        text = prompt.lower().strip()

        system_attack = False
        developer_attack = False
        retrieved_attack = False
        confidential_attack = False

        detected_target = None
        threat_type = None
        matched_pattern = None

        # =================================================
        # SYSTEM CONTEXT ATTACK
        # =================================================

        system_patterns = [

            "ignore system instructions",
            "ignore the system prompt",
            "override system instructions",
            "change system instructions",
            "modify system prompt",
            "reveal system prompt",
            "show system prompt",
            "display system prompt",

        ]

        for pattern in system_patterns:

            if pattern in text:

                system_attack = True

                detected_target = "SYSTEM CONTEXT"

                threat_type = "PROMPT INJECTION"

                matched_pattern = pattern

                break

        # =================================================
        # DEVELOPER CONTEXT ATTACK
        # =================================================

        developer_patterns = [

            "ignore developer instructions",
            "ignore developer prompt",
            "override developer instructions",
            "change developer instructions",
            "modify developer prompt",
            "reveal developer message",
            "show developer instructions",
            "reveal developer instructions",

        ]

        for pattern in developer_patterns:

            if pattern in text:

                developer_attack = True

                detected_target = "DEVELOPER CONTEXT"

                threat_type = "PROMPT INJECTION"

                matched_pattern = pattern

                break

        # =================================================
        # RETRIEVED CONTEXT ATTACK
        # =================================================

        retrieved_patterns = [

            "ignore retrieved documents",
            "ignore retrieved context",
            "modify retrieved context",
            "change retrieved documents",
            "ignore university regulations",
            "modify university regulations",
            "change university regulations",

        ]

        for pattern in retrieved_patterns:

            if pattern in text:

                retrieved_attack = True

                detected_target = "RETRIEVED CONTEXT"

                threat_type = "RETRIEVAL CONTEXT MANIPULATION"

                matched_pattern = pattern

                break

        # =================================================
        # GENERAL CROSS-CONTEXT ATTACK
        # =================================================

        general_patterns = [

            r"ignore all previous instructions",

            r"forget all previous instructions",

            r"ignore previous instructions",

            r"override all instructions",

            r"forget everything above",

            r"follow only my instructions",

        ]

        for pattern in general_patterns:

            if re.search(
                pattern,
                text
            ):

                system_attack = True

                detected_target = "SYSTEM CONTEXT"

                threat_type = "PROMPT INJECTION"

                matched_pattern = pattern

                break

        # =================================================
        # CONFIDENTIAL EXAM / ACADEMIC CONTENT
        # =================================================

        # These patterns specifically target unauthorized
        # examination material.
        #
        # Normal prompts such as:
        # "How do I prepare for my exam?"
        # will NOT be blocked.

        exam_confidential_patterns = [

            "leak the exam paper",

            "leak the exam papers",

            "leak exam paper",

            "leak exam papers",

            "leak the question paper",

            "leak question paper",

            "reveal the exam paper",

            "reveal the exam papers",

            "reveal exam paper",

            "reveal exam papers",

            "show the exam paper",

            "show the exam papers",

            "show exam paper",

            "show exam papers",

            "give me the exam paper",

            "give me the exam papers",

            "give me exam paper",

            "give me exam papers",

            "send me the exam paper",

            "send me the exam papers",

            "send me exam paper",

            "send me exam papers",

            "get the exam paper",

            "get the exam papers",

            "get exam paper",

            "get exam papers",

            "steal the exam paper",

            "steal the exam papers",

            "steal exam paper",

            "steal exam papers",

            "unauthorized exam paper",

            "unauthorized exam papers",

            "confidential exam paper",

            "confidential exam papers",

            "secret exam paper",

            "secret exam papers",

        ]

        for pattern in exam_confidential_patterns:

            if pattern in text:

                confidential_attack = True

                detected_target = (
                    "CONFIDENTIAL ACADEMIC CONTENT"
                )

                threat_type = (
                    "CONFIDENTIAL INFORMATION REQUEST"
                )

                matched_pattern = pattern

                break

        # =================================================
        # USER CONTEXT
        # =================================================

        user_context_active = bool(
            prompt.strip()
        )

        # =================================================
        # FINAL ATTACK DECISION
        # =================================================

        attack_detected = (

            system_attack

            or

            developer_attack

            or

            retrieved_attack

            or

            confidential_attack

        )

        if attack_detected:

            result = "BLOCK"

        else:

            result = "PASSED"

        # =================================================
        # CONTEXT STATUS
        # =================================================

        contexts = {

            "system": {

                "status":
                    "PROTECTED",

                "modifiable":
                    False

            },

            "developer": {

                "status":
                    "PROTECTED",

                "modifiable":
                    False

            },

            "retrieved": {

                "status":
                    "AVAILABLE",

                "modifiable":
                    False

            },

            "user": {

                "status":
                    "ACTIVE",

                "modifiable":
                    True

            }

        }

        # =================================================
        # CONTEXT SCORE
        # =================================================

        if attack_detected:

            context_score = 20

        else:

            context_score = 100

        # =================================================
        # RETURN RESULT
        # =================================================

        return {

            "contexts":
                contexts,

            "context_score":
                context_score,

            "attack_detected":
                attack_detected,

            "target":
                detected_target,

            "result":
                result,

            "threat_type":
                threat_type,

            "matched_pattern":
                matched_pattern,

            "confidential_attack":
                confidential_attack,

            "system_attack":
                system_attack,

            "developer_attack":
                developer_attack,

            "retrieved_attack":
                retrieved_attack,

            "system_context":
                self.system_context,

            "developer_context":
                self.developer_context,

            "retrieved_context":
                self.retrieved_context,

            "user_context":
                prompt,

        }

    # =====================================================
    # MAIN VALIDATE FUNCTION
    # =====================================================

    def validate(self, prompt):

        return self.validate_mcp_context(
            prompt
        )