# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Registry of tokendito credential backends.

Built-in backends are imported lazily, so a backend whose module (or its dependencies)
is not installed does not prevent the others from working. Third-party code can add
backends with the ``register_backend`` decorator.

A backend module may also define a module-level ``add_arguments(parser)`` function. It is
called by ``add_backend_arguments`` while the CLI parser is built, so backends can add their
own argparse groups. Argument ``dest`` values must be ``<config section>_<key>``.
"""

import importlib
import logging
import sys

logger = logging.getLogger(__name__)

_BUILTIN = {
    "aws": "tokendito.backends.aws",
    "gcp": "tokendito.backends.gcp",
    "azure": "tokendito.backends.azure",
}

_REGISTRY = {}


def register_backend(name):
    """Register a CredentialBackend subclass under a name.

    :param name: registry key, e.g. "aws".
    :return: class decorator.
    """

    def decorator(cls):
        cls.name = name
        _REGISTRY[name] = cls
        return cls

    return decorator


def _import_backend_module(name):
    """Import the module of a built-in backend.

    :param name: backend name.
    :return: module, or None if it cannot be imported.
    """
    module_name = _BUILTIN.get(name)
    if module_name is None:
        return None
    try:
        return importlib.import_module(module_name)
    except ImportError as err:
        logger.debug(f"Backend '{name}' is not available: {err}")
        return None


def _resolve(name):
    """Find the class registered for a backend, importing it if necessary.

    :param name: backend name.
    :return: backend class or None.
    """
    if name not in _REGISTRY:
        _import_backend_module(name)
    return _REGISTRY.get(name)


def available_backends():
    """List the backends that can be used.

    :return: sorted list of backend names whose module can be imported.
    """
    names = set(_REGISTRY) | set(_BUILTIN)
    return sorted(name for name in names if _resolve(name) is not None)


def get_backend(name):
    """Retrieve a backend class by name. Exits if the backend is unknown or unavailable.

    :param name: backend name.
    :return: CredentialBackend subclass. Instantiate it with the Config object.
    """
    backend = _resolve(name)
    if backend is None:
        logger.error(
            f"Backend '{name}' is not available. "
            f"Available backends: {', '.join(available_backends())}."
        )
        sys.exit(1)
    return backend


def add_backend_arguments(parser):
    """Let each importable backend module add its own command line arguments.

    :param parser: argparse.ArgumentParser
    :return: list of backend names whose add_arguments hook was called.
    """
    called = []
    for name in sorted(_BUILTIN):
        module = _import_backend_module(name)
        hook = getattr(module, "add_arguments", None)
        if callable(hook):
            hook(parser)
            called.append(name)
    return called


def get_module_names():
    """List the logger names of the built-in backend modules.

    :return: list of module names.
    """
    return list(_BUILTIN.values())
