from verify_artifact import Policy

POLICY = Policy(
    repository='cryptolabsza/cryptolabs-proxy',
    repository_id=1140353276,
    workflow_path='.github/workflows/publish.yml',
    recipe_ref='cryptolabsza/cryptolabs-proxy/.github/workflows/ci-python-build-recipe.yml@6a6a846245461b9a7ae593bbf1720b8753bfb957',
    producer_job='cpu-build / build',
    group_id=11,
    build_label='ci-linux-cpu-v1-r1140353276',
    artifact_kind='pypi',
    artifact_stem='cpu-python',
)
PROJECT = 'cryptolabs-proxy'
PROJECT_FILE = 'pyproject.toml'
MIRROR_GITHUB = True
