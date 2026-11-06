from pythonforandroid.recipe import CompiledComponentsPythonRecipe


class Argon2Recipe(CompiledComponentsPythonRecipe):
    name = 'argon2-cffi'
    version = '20.1.0'
    url = 'https://files.pythonhosted.org/packages/source/a/argon2-cffi/argon2-cffi-{version}.tar.gz'
    depends = ['setuptools', 'cffi', 'six']
    call_hostpython_via_targetpython = False
    build_cmd = 'build'

    def get_recipe_env(self, arch):
        env = super().get_recipe_env(arch)
        env['ARGON2_CFFI_USE_SSE2'] = '0'
        return env


recipe = Argon2Recipe()
