"""
Pydantic data schemas for NO ENTRY Practical Academy.
Defines tracks, rooms, tasks, quizzes, submissions, and feedback.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, model_validator


class TrackEnum(str, Enum):
    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"
    DETECTION = "detection"


class RoomStatus(str, Enum):
    IMPLEMENTED = "implemented"
    IN_DEVELOPMENT = "in_development"
    PLANNED = "planned"


class TaskType(str, Enum):
    CONCEPT = "concept"
    COMMAND = "command"
    FLAG = "flag"
    FIX = "fix"
    QUIZ = "quiz"
    QUESTION = "question"
    REMEDIATION = "fix"


class QuizQuestion(BaseModel):
    id: str
    question: str
    options: List[str]
    correct_index: int = 0
    correct_option_index: Optional[int] = None
    explanation: str

    @model_validator(mode="before")
    @classmethod
    def resolve_correct_index(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "correct_option_index" in data and "correct_index" not in data:
                data["correct_index"] = data["correct_option_index"]
            elif "correct_index" in data and "correct_option_index" not in data:
                data["correct_option_index"] = data["correct_index"]
        return data


class TaskDefinition(BaseModel):
    task_id: str
    order: int
    title: str
    instructions: str
    task_type: TaskType = TaskType.FLAG
    question: Optional[str] = None
    hint: Optional[str] = None
    xp_reward: int = 50
    # Validation rules (strictly evaluated on backend, never leaked to client)
    accepted_answers: List[str] = Field(default_factory=list)
    accepted_regex: Optional[str] = None
    mistake_explanations: Dict[str, str] = Field(default_factory=dict)
    quiz_questions: List[QuizQuestion] = Field(default_factory=list)

    def client_view(self) -> Dict[str, Any]:
        """Strip validation secrets, correct answers, and regex before sending to browser."""
        data = self.model_dump(exclude={"accepted_answers", "accepted_regex"})
        if self.quiz_questions:
            data["quiz_questions"] = [
                {
                    "id": q.id,
                    "question": q.question,
                    "options": q.options,
                    # correct_index omitted for client
                    "explanation": q.explanation,
                }
                for q in self.quiz_questions
            ]
        return data


class RoomConcept(BaseModel):
    overview: str
    simple_analogy: str
    technical_term: str
    technical_definition: str
    cybersecurity_context: str
    why_it_matters: str
    demonstration: str
    remediation_guide: str


class RoomDefinition(BaseModel):
    room_id: str
    track: TrackEnum
    room_number: int
    title: str
    short_description: str
    difficulty: str = "Beginner"  # Beginner | Intermediate | Advanced
    estimated_duration: str = "45 min"
    prerequisites: List[str] = Field(default_factory=list)
    required_practical_skills: List[str] = Field(default_factory=list)
    required_lab_type: str = "container_duo"  # container_duo | single_host | simulated | analytical
    status: RoomStatus = RoomStatus.PLANNED
    learning_objectives: List[str] = Field(default_factory=list)
    assessment_criteria: List[str] = Field(default_factory=list)
    completion_requirements: List[str] = Field(default_factory=list)
    total_xp: int = 250
    concept: Optional[RoomConcept] = None
    tasks: List[TaskDefinition] = Field(default_factory=list)
    target_app_type: Optional[str] = None
    default_port: int = 8089

    def client_summary(self) -> Dict[str, Any]:
        """Summary card representation for the academy curriculum browser."""
        return {
            "room_id": self.room_id,
            "track": self.track.value,
            "room_number": self.room_number,
            "title": self.title,
            "short_description": self.short_description,
            "difficulty": self.difficulty,
            "estimated_duration": self.estimated_duration,
            "status": self.status.value,
            "is_available": self.status == RoomStatus.IMPLEMENTED,
            "total_xp": self.total_xp,
            "task_count": len(self.tasks),
            "prerequisites": self.prerequisites,
            "skills": self.required_practical_skills,
        }

    def client_detail(self) -> Dict[str, Any]:
        """Full detail for room workspace with answers scrubbed."""
        summary = self.client_summary()
        summary["learning_objectives"] = self.learning_objectives
        summary["assessment_criteria"] = self.assessment_criteria
        summary["completion_requirements"] = self.completion_requirements
        summary["concept"] = self.concept.model_dump() if self.concept else None
        summary["tasks"] = [t.client_view() for t in self.tasks]
        summary["default_port"] = self.default_port
        return summary


class TaskSubmission(BaseModel):
    answer: Optional[str] = ""
    quiz_answers: Optional[Dict[str, int]] = None  # question_id -> chosen_index


class TaskSubmissionResult(BaseModel):
    task_id: str
    completed: bool
    is_correct: bool
    feedback: str
    mistake_explanation: Optional[str] = None
    earned_xp: int = 0
    attempts: int = 1
    room_completed: bool = False
    new_room_status: str = "IN_PROGRESS"
    total_user_xp: int = 0

