"""Safe, non-personal starter questions for the first-use authoring flow."""

from __future__ import annotations


QUESTION_STARTERS: tuple[dict[str, str], ...] = (
    {
        "key": "shared_activity",
        "title": "我们一起参加过线下活动吗？",
        "text": "我们一起参加过线下活动吗？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "共同经历",
        "hint": "适合大多数朋友关系，先从共同经历开始。",
    },
    {
        "key": "shared_interest",
        "title": "我们一起玩过同一款游戏吗？",
        "text": "我们一起玩过同一款游戏吗？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "共同兴趣",
        "hint": "用一个轻松的共同记忆确认关系。",
    },
    {
        "key": "first_meeting",
        "title": "我们在工作或学习上认识吗？",
        "text": "我们在工作或学习上认识吗？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "相识场景",
        "hint": "不用写具体地点，直接选择最接近的答案。",
    },
    {
        "key": "shared_place",
        "title": "我们去过同一个地方吗？",
        "text": "我们去过同一个地方吗？",
        "privacy_level": "L2_PRIVATE",
        "facet_tag": "共同地点",
        "hint": "适合旅行或常去地点的共同记忆。",
    },
    {
        "key": "shared_friend",
        "title": "我们有共同的朋友吗？",
        "text": "我们有共同的朋友吗？",
        "privacy_level": "L1_RELATION",
        "facet_tag": "关系网络",
        "hint": "只确认是否有共同朋友，不填写姓名。",
    },
)


def get_question_starter(key: str) -> dict[str, str] | None:
    """Return a copy so route code cannot mutate the global catalog."""

    for item in QUESTION_STARTERS:
        if item["key"] == key:
            return dict(item)
    return None
