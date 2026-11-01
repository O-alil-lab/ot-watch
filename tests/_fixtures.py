"""Jeu de données figé pour les tests (tests/fixtures/data), copié dans un dossier temporaire
pour qu'aucun test n'écrive dans le vrai data/ ni ne dépende d'une collecte réseau."""
import atexit
import os
import shutil
import tempfile

FIXTURE_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "data")


def fixture_data_dir():
    tmp = tempfile.mkdtemp(prefix="otwatch-test-data-")
    atexit.register(shutil.rmtree, tmp, True)
    dst = os.path.join(tmp, "data")
    shutil.copytree(FIXTURE_DATA, dst)
    return dst
