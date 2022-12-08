# SPDX-FileCopyrightText: 2020 The Kapitan Authors <kapitan-admins@googlegroups.com>
#
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from functools import lru_cache

import jsonschema
import requests
import yaml
from kapitan import defaults
from kapitan.errors import KubernetesManifestValidationError, RequestUnsuccessfulError
from kapitan.utils import make_request
from kapitan.validator.base import Validator

logger = logging.getLogger(__name__)


class KubernetesManifestValidator(Validator):
    def __init__(self, cache_dir, **kwargs):
        super().__init__(cache_dir, **kwargs)

    def validate(self, validate_files, **kwargs):
        """
        validates manifests at validate_paths against json schema as specified by 'version' in kwargs.
        raises KubernetesManifestValidationError encountering the first validation error
        """

        version = kwargs.get("version", defaults.DEFAULT_KUBERNETES_VERSION)
        validators = {}
        fail_on_error = kwargs.get("fail_on_error", False) 
        ignores = kwargs.get("ignore", {})
        ignored_kinds = ignores.get("kinds", defaults.DEFAULT_IGNORED_KINDS)
        logger.debug(f"Ignore configuration: {ignores}")
        ignored_files = ignores.get("files", [])
        for validate_file in validate_files:
            if validate_files in ignored_files:
              logger.debug(f"Validation: skipping file {validate_file} because of ignore.files")
              continue
                
            logger.debug(f"Validation: processing file {validate_file}")
            with open(validate_file, "r") as fp:
                for validate_instance in yaml.safe_load_all(fp.read()):
                    kind = validate_instance.get("kind")
                    try:
                        annotation_ignore_validation = validate_instance.metadata.annotations.get(defaults.VALIDATION_IGNORE_ANNOTATION)
                        if annotation_ignore_validation:
                            continue
                    except AttributeError:
                        pass
                        
                    if kind is None:
                        error_message = f"Loaded yaml document {validate_file} lacks `kind`"
                        raise KubernetesManifestValidationError(error_message)
                    elif kind in ignored_kinds:
                        logger.debug(f"Validation: skipping kind {kind} inside {validate_file} because of ignore.kinds")
                        continue
                    
                    logger.debug(f"Validation: detected kind {kind}")

                    validator = validators.setdefault(
                        kind, jsonschema.Draft4Validator(self._get_schema(kind, version))
                    )
                    errors = sorted(validator.iter_errors(validate_instance), key=lambda e: e.path)
                    if errors:
                        error_message = "invalid '{}' manifest at {}\n".format(kind, validate_file)
                        error_message += "\n".join(
                            ["{} {}".format(list(error.path), error.message) for error in errors]
                        )
                        if fail_on_error:
                            raise KubernetesManifestValidationError(error_message)
                        else:
                            logger.info(error_message)
                    else:
                        logger.debug("Validation: manifest validation successful for %s", validate_file)

    @lru_cache(maxsize=256)
    def _get_schema(self, kind, version):
        """gets json validation schema from web or cache"""
        schema = self._get_cached_schema(kind, version)
        if schema is None:
            schema = self._get_schema_from_web(kind, version)
            self._cache_schema(kind, version, schema)
        return schema

    def _cache_schema(self, kind, version, schema):
        cache_path = self._get_cache_path(kind, version)
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w") as fp:
            yaml.safe_dump(schema, stream=fp, default_flow_style=False)

    def _get_cached_schema(self, kind, version):
        cache_path = self._get_cache_path(kind, version)
        if os.path.isfile(cache_path):
            with open(cache_path, "r") as fp:
                return yaml.safe_load(fp.read())
        else:
            return None

    def _get_schema_from_web(self, kind, version):
        url = self._get_request_url(kind, version)
        logger.debug("Validation: fetching schema from %s", url)
        try:
            content, _ = make_request(url)
        except requests.exceptions.HTTPError:
            raise RequestUnsuccessfulError(
                "Validation: schema failed to fetch from {}"
                "\nThe specified version '{}' or kind '{}' may not be supported".format(url, version, kind)
            )
        logger.debug("Validation: schema fetched  from %s", url)
        return yaml.safe_load(content)

    def _get_request_url(self, kind, version):
        return "https://kubernetesjsonschema.dev/" + defaults.FILE_PATH_FORMAT.format(version, kind)

    def _get_cache_path(self, kind, version):
        return os.path.join(self.cache_dir, defaults.FILE_PATH_FORMAT.format(version, kind))
