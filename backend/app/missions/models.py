"""
Pydantic models defining NO ENTRY interactive and cinematic missions,
validation rules, and API response schemas.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator


MISSION_STAGES = [
    "briefing",
    "attacker",
    "flag",
    "side_switch",
    "defender",
    "fix",
    "verify",
    "debrief",
]


class MissionQuizQuestion(BaseModel):
    id: str
    question: str
    options: List[str] = Field(..., min_length=2, max_length=6)
    correct_index: int = Field(..., ge=0)
    explanation: str

    @model_validator(mode="after")
    def _validate_index(self):
        if self.correct_index >= len(self.options):
            raise ValueError(f"correct_index {self.correct_index} out of bounds for quiz {self.id}")
        return self


class MissionLogEntry(BaseModel):
    timestamp: Optional[str] = None
    source: str = "apache"
    event_type: str = "attack"
    technique_id: str = "T1190"
    source_ip: str = "185.220.101.4"
    target_host: str = "web01"
    raw_line: str
    structured: Dict[str, Any] = Field(default_factory=dict)
    benign: bool = False
    is_true_positive: bool = False


class MissionStep(BaseModel):
    id: str
    order: int
    title: str
    goal: str
    tool: str
    accepted_patterns: List[str] = Field(..., min_length=1)
    sample_command: str
    expected_output: List[str]
    wrong_command_hint: str = "Command did not hit the expected target/vector. Check the step goal or request a hint."
    hints: List[str] = Field(..., min_length=3, max_length=3)
    mitre_id: str
    generated_logs: List[MissionLogEntry] = Field(default_factory=list)
    sim_event: Optional[Dict[str, Any]] = None
    shop_response: Optional[Dict[str, Any]] = None


class MissionRuleChallenge(BaseModel):
    prompt: str
    expected_mitre_id: str
    mitre_choices: List[Dict[str, str]]
    template_yaml: str
    reference_solution_yaml: str
    required_min_hits: int = Field(default=1, ge=1)
    max_false_positives: int = Field(default=0, ge=0)
    benign_baseline_logs: List[MissionLogEntry] = Field(default_factory=list)


class MissionFixOption(BaseModel):
    id: str
    label: str
    code_snippet: str
    is_correct: bool
    explanation: str


class MissionFixConfig(BaseModel):
    prompt: str
    language: str = "python"
    vulnerable_code: str
    options: List[MissionFixOption] = Field(..., min_length=2)
    accepted_patch_patterns: List[str] = Field(default_factory=list)
    patch_explanation: str = ""

    @model_validator(mode="after")
    def _validate_correct_option(self):
        if not any(o.is_correct for o in self.options):
            raise ValueError("MissionFixConfig must contain at least one correct fix option.")
        return self


class MissionVerifyConfig(BaseModel):
    attack_command: str
    blocked_output: List[str]
    blocked_log_line: str
    waf_control: str
    explanation: str


class MissionDebrief(BaseModel):
    why_it_worked: str
    how_it_was_stopped: str
    mitre_summary: str
    key_takeaways: List[str] = Field(default_factory=list)


class CinematicWalkthroughLine(BaseModel):
    phase: str
    delay: float = 1.2
    mitre_id: Optional[str] = None
    speaker: str = "SYSTEM"
    text: str


class MissionDefinition(BaseModel):
    id: str
    order: int
    title: str
    subtitle: str
    description: str
    track: Literal["attacker", "defender", "purple"] = "purple"
    difficulty: Literal["BEGINNER", "INTERMEDIATE", "ADVANCED"] = "BEGINNER"
    mitre_ids: List[str] = Field(..., min_length=1)
    xp_reward: int = Field(..., gt=0)
    playable: bool = True
    target_host: str
    target_ip: str
    story: str
    scope: str = "10.0.0.0/16 Virtual Corporate Range (Isolated). Attacks stay inside the range."
    briefing_lines: List[str] = Field(..., min_length=1)
    has_shop_widget: bool = False
    cinematic_walkthrough: List[CinematicWalkthroughLine] = Field(default_factory=list)
    steps: List[MissionStep] = Field(default_factory=list)
    flag: str = ""
    rule_challenge: Optional[MissionRuleChallenge] = None
    fix: Optional[MissionFixConfig] = None
    verify: Optional[MissionVerifyConfig] = None
    debrief: Optional[MissionDebrief] = None
    quiz: List[MissionQuizQuestion] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_mission_completeness(self):
        if self.playable:
            if len(self.steps) < 3:
                raise ValueError(f"Playable mission '{self.id}' must define at least 3 steps.")
            if not (self.flag.startswith("NOENTRY{") and self.flag.endswith("}")):
                raise ValueError(f"Playable mission '{self.id}' must define a NOENTRY{{...}} flag.")
            if not self.rule_challenge:
                raise ValueError(f"Playable mission '{self.id}' missing rule_challenge.")
            if not self.fix:
                raise ValueError(f"Playable mission '{self.id}' missing fix.")
            if not self.verify:
                raise ValueError(f"Playable mission '{self.id}' missing verify.")
            if not self.debrief:
                raise ValueError(f"Playable mission '{self.id}' missing debrief.")
            if len(self.quiz) != 5:
                raise ValueError(f"Playable mission '{self.id}' must define exactly 5 quiz questions.")
        else:
            if len(self.cinematic_walkthrough) < 4:
                raise ValueError(f"Cinematic mission '{self.id}' must define at least 4 walkthrough lines.")
            if not self.debrief:
                raise ValueError(f"Cinematic mission '{self.id}' missing debrief.")
        return self

