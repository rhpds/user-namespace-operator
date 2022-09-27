#!/usr/bin/env python

import asyncio
import collections
import copy
import kopf
import kubernetes_asyncio
import logging
import os
import re
import time

from config import (
    authorization_v1_api,
    check_interval,
    core_v1_api,
    custom_objects_api,
    operator_api_version,
    operator_cluster_admin,
    operator_domain,
    operator_namespace,
    operator_service_account_name,
    operator_version,
    rbac_authorization_v1_api,
)

from configure_kopf_logging import configure_kopf_logging
from infinite_relative_backoff import InfiniteRelativeBackoff

from group import Group
from user import User
from user_namespace import UserNamespace
from user_namespace_config import UserNamespaceConfig

@kopf.on.startup()
async def startup(logger, settings: kopf.OperatorSettings, **_):
    # Never give up from network errors
    settings.networking.error_backoffs = InfiniteRelativeBackoff()

    # Store last handled configuration in status
    settings.persistence.diffbase_storage = kopf.StatusDiffBaseStorage(field='status.diffBase')

    # Use operator domain as finalizer
    settings.persistence.finalizer = operator_domain

    # Store progress in status.
    settings.persistence.progress_storage = kopf.StatusProgressStorage(field='status.kopf.progress')

    # Only create events for warnings and errors
    settings.posting.level = logging.WARNING

    # Disable scanning for CustomResourceDefinitions updates
    settings.scanning.disabled = True

    # Configure logging
    configure_kopf_logging()

    if operator_cluster_admin:
        logger.info("Running as cluster-admin")
    else:
        logger.info("Running without cluster-admin privileges")

    # Preload resources that are needed in memory at runtime
    await Group.preload()
    await UserNamespaceConfig.preload()
    await UserNamespace.preload()


@kopf.on.event('user.openshift.io', 'v1', 'groups')
async def group_event(event, logger, **_):
    definition = event.get('object')

    if not definition \
    or definition['kind'] != 'Group':
        return

    if event['type'] == 'DELETED':
        group = Group.unregister(definition['metadata']['name'])
        if group:
            for user_name in group.users:
                try:
                    user = await User.get(user_name)
                    await user.manage(logger=logger)
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status != 404:
                        raise
    else:
        group = await Group.register(definition)
        for user_name in group.users ^ group.prev_users:
            try:
                user = await User.get(user_name)
                await user.manage(logger=logger)
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status != 404:
                    raise


@kopf.on.event('user.openshift.io', 'v1', 'users')
async def user_event(event, logger, **_):
    definition = event.get('object')

    if not definition \
    or definition['kind'] != 'User':
        return

    user = await User.register(definition=definition)

    if event['type'] == 'DELETED':
        await user.handle_delete(logger=logger)
        user.unregister()
    else:
        await user.manage(logger=logger)


@kopf.on.create(operator_domain, operator_version, 'usernamespaces', id='usernamespace_create')
@kopf.on.resume(operator_domain, operator_version, 'usernamespaces', id='usernamespace_resume')
@kopf.on.update(operator_domain, operator_version, 'usernamespaces', id='usernamespace_update')
async def usernamespace_handler(logger, name, spec, status, uid, **_):
    user_namespace = await UserNamespace.register(name=name, spec=spec, status=status, uid=uid)
    await user_namespace.get_user_and_manage(logger=logger)


@kopf.daemon(operator_domain, operator_version, 'usernamespaces', cancellation_timeout=1)
async def usernamespace_daemon(logger, name, spec, status, stopped, uid, **_):
    '''
    Periodically manage resources for namespace check if UserNamespace should be deleted following User deletion.
    '''
    user_namespace = await UserNamespace.register(name=name, spec=spec, status=status, uid=uid)
    try:
        while not stopped:
            await user_namespace.get_user_and_manage(logger=logger)
            config = await user_namespace.get_config()
            await asyncio.sleep(config.management_interval_seconds if config else 600)
    except asyncio.CancelledError:
        pass

    
@kopf.on.create(operator_domain, operator_version, 'usernamespaceconfigs', id='usernamespaceconfig_create')
@kopf.on.update(operator_domain, operator_version, 'usernamespaceconfigs', id='usernamespaceconfig_update')
async def usernamespaceconfig_handler(logger, name, spec, status, uid, **_):
    user_namespace_config = await UserNamespaceConfig.register(name=name, spec=spec, status=status, uid=uid)
    await user_namespace_config.manage_user_namespaces(logger=logger)
    await user_namespace_config.check_autocreate_user_namespaces(logger=logger)

@kopf.on.delete(operator_domain, operator_version, 'usernamespaceconfigs')
async def usernamespaceconfig_delete(logger, name, **_):
    await UserNamespaceConfig.unregister_config(name=name)

@kopf.daemon(operator_domain, operator_version, 'usernamespaceconfigs', cancellation_timeout=1)
async def usernamespaceconfig_daemon(logger, name, spec, status, stopped, uid, **_):
    user_namespace_config = await UserNamespaceConfig.register(name=name, spec=spec, status=status, uid=uid)
    try:
        while not stopped:
            await user_namespace_config.check_autocreate_user_namespaces(logger=logger)
            await asyncio.sleep(user_namespace_config.management_interval_seconds)
    except asyncio.CancelledError:
        pass
