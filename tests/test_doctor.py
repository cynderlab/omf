# tests/test_doctor.py
from omf.doctor import run_doctor_checks


def test_all_required_ok_llm_missing_is_warn_exit_zero():
    code, lines = run_doctor_checks(
        env={},
        which_uv=lambda: "/usr/bin/uv",
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=False,
    )
    assert code == 0
    text = "\n".join(lines)
    assert "OK       uv" in text
    assert "OK       python" in text
    assert "OK       deps" in text
    assert "WARN     env-file" in text
    assert "WARN     OMF_LLM_API_KEY" in text
    assert "sk-secret" not in text


def test_missing_uv_exits_one():
    code, lines = run_doctor_checks(
        env={},
        which_uv=lambda: None,
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 1
    assert any(line.startswith("MISSING  uv") for line in lines)


def test_old_python_exits_one():
    code, _ = run_doctor_checks(
        env={},
        which_uv=lambda: "/uv",
        python_version=(3, 11),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 1


def test_api_key_never_printed():
    code, lines = run_doctor_checks(
        env={
            "OMF_LLM_BASE_URL": "https://openrouter.ai/api/v1",
            "OMF_LLM_API_KEY": "sk-secret-value",
            "OMF_LLM_MODEL": "x",
            "OMF_LLM_API_STYLE": "openai",
        },
        which_uv=lambda: "/uv",
        python_version=(3, 13),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert code == 0
    joined = "\n".join(lines)
    assert "sk-secret-value" not in joined
    assert "OK       OMF_LLM_API_KEY" in joined


def test_bad_api_style_is_warn():
    _, lines = run_doctor_checks(
        env={"OMF_LLM_API_STYLE": "haystack"},
        which_uv=lambda: "/uv",
        python_version=(3, 12),
        try_import=lambda: True,
        env_file_exists=True,
    )
    assert any("WARN     OMF_LLM_API_STYLE" in line for line in lines)
