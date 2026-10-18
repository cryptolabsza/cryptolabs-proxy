from verify_artifact import Policy
from transport import main
POLICY=Policy(repository='cryptolabsza/cryptolabs-proxy',repository_id=1140353276,workflow_path='.github/workflows/docker-build.yml',recipe_ref='cryptolabsza/cryptolabs-proxy/.github/workflows/ci-image-build-recipe.yml@7eb7e476b362c3f5eaeee73b05d9bf95fe508764',producer_job='build / build',group_id=11,build_label='ci-linux-cpu-v1-r1140353276',artifact_kind='oci',artifact_stem='cpu-image')
IMAGES=['cryptolabs-proxy']
if __name__=='__main__':raise SystemExit(main(POLICY,IMAGES))
