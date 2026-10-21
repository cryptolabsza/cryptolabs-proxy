from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/cryptolabs-proxy',repository_id=1140353276,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/cryptolabs-proxy/.github/workflows/ci-image-build-recipe.yml@aadf8cccc44806f9007b20133c4c92736e33baa6',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1140353276',artifact_kind='oci',artifact_stem='cpu-image',transport_schema=2)
IMAGES=['cryptolabs-proxy']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
