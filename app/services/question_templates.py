"""Safe, non-personal starter questions for the first-use authoring flow."""

from __future__ import annotations


QUESTION_STARTERS: tuple[dict[str, str], ...] = (
    {
        "key": "shared_activity",
        "title": "一起做过什么",
        "text": "我们是否一起参加过线下活动？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "共同经历",
        "hint": "适合大多数朋友关系，先从这里开始。",
    },
    {
        "key": "shared_interest",
        "title": "共同兴趣",
        "text": "我们是否一起玩过同一款游戏？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "共同兴趣",
        "hint": "适合用一个轻松的共同记忆确认关系。",
    },
    {
        "key": "first_meeting",
        "title": "第一次认识",
        "text": "我们是否曾经在工作或学习上认识？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "相识场景",
        "hint": "不需要写具体地点，避免暴露多余信息。",
    },
    {
        "key": "shared_place",
        "title": "共同去过的地方",
        "text": "我们是否去过同一个地方？",
        "privacy_level": "L2_PRIVATE",
        "facet_tag": "共同地点",
        "hint": "如果你们有旅行或常去地点，可以选择这一题。",
    },
    {
        "key": "shared_friend",
        "title": "共同认识的人",
        "text": "我们是否有共同的朋友？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "关系网络",
        "hint": "只确认是否有共同朋友，不要求填写姓名。",
    },
)


def get_question_starter(key: str) -> dict[str, str] | None:
    """Return a copy so route code cannot mutate the global catalog."""

    for item in QUESTION_STARTERS:
        if item["key"] == key:
            return dict(item)
    return None
