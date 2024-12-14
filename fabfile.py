# -*- coding: utf-8 -*-

import os
import shutil
import sys

from pip._vendor.distlib.compat import raw_input

from fabric.colors import blue, cyan, green, magenta, red, yellow
from fabric.decorators import task
from fabric.operations import local
from fabric.state import env
from fabric.utils import puts


# ===========
# = GLOBALS =
# ===========
env.project_name = os.path.basename(os.path.dirname(__file__))
env.colorize_errors = True


# ============
# =  Hello   =
# ============
@task(default=True, alias='别名测试')
def hello():
    puts('*' * 50)
    puts(cyan('  Fabric 使用指南\n'))
    puts(green('  查看所有命令: fab -l'))
    puts(green('  查看命令: fab -d 命令'))
    puts(yellow('  带参数命令请输入: fab 命令:参数'))
    puts('  Project Name: {.project_name}'.format(env))  # 这种写法直观.
    puts('*' * 50)


@task()
def update_project():
    local('curl -fsSL https://raw.githubusercontent.com/nypisces/Free/master/gitignore/Swift.gitignore > .gitignore')
    local_proxy('pod update')


def local_proxy(command):
    local('proxychains4 {}'.format(command))


# =========
# =  git  =
# =========
@task
def commit_and_sync(comment=None):
    """git commit and sync"""
    output_list = local('git status', True).split('\n')
    branch = output_list[0].replace('On branch ', '')
    if branch in ['develop', 'main']:
        puts('不允许在 {} 分支 用 {} 命令直接操作'.format(yellow(branch), get_function_name()))
    elif 'nothing to commit' in output_list[-1]:
        puts('{} 分支没有变动, 不需要提交'.format(yellow(branch)))
        if 'is ahead of' in output_list[1]:
            puts('同步 {} 分支'.format(yellow(branch)))
            local_proxy('git push')
    else:
        local('git reset')
        delete_files = [x.strip() for x in output_list if x.find('deleted:') != -1]
        for file in delete_files:
            filename = file.split(':')[1].strip()
            local('git rm {}'.format(filename))
        local('git add .')
        if not comment:
            comment = raw_input('请输入提交的注解: ')
        local('git status')
        local('git commit -m "{}"'.format(comment))
        local_proxy('git push')


@task
def update_from_develop():
    """从 develop 更新到当前分支"""
    output_list = local('git status', True).split('\n')
    branch = output_list[0].replace('On branch ', '')
    if branch in ['develop', 'main']:
        puts('不允许在 {} 分支 用 {} 命令直接操作'.format(yellow(branch), get_function_name()))
    elif 'nothing to commit' in output_list[-1]:
        local_proxy('git pull origin develop')
    else:
        local('git status')
        puts('当前 {} 分支有更新未提交, 请先执行 fab git_commit 命令提交'.format(yellow(branch)))


@task
def update_to_develop():
    """从当前分支更新到 develop """
    output_list = local('git status', True).split('\n')
    branch = output_list[0].replace('On branch ', '')
    if branch in ['develop', 'main']:
        puts('不允许在 {} 分支 用 {} 命令直接操作'.format(yellow(branch), get_function_name()))
    elif 'nothing to commit' in output_list[-1]:
        confirm = raw_input('是否已经update_from_develop? [y/N]: '.format(yellow(branch)))
        if confirm.lower() in ['ok', 'y', 'yes']:
            puts('从 {} 合并到 develop'.format(yellow(branch)))
            local('git checkout develop')
            local_proxy('git pull')
            local('git merge {}'.format(branch))
            local_proxy('git push')
            local('git checkout {}'.format(branch))
    else:
        local('git status')
        puts('当前 {} 分支有更新未提交, 请先执行 fab git_commit 命令提交'.format(yellow(branch)))


# ========
# = pypi =
# ========
@task
def upload_to_pypi():
    """自动打包上传到pypi"""
    safe_local_delete('dist')
    local('python setup.py sdist')
    local('twine upload dist/*')


# ============
# = 工具方法  =
# ============
def safe_local_delete(path):
    if os.path.exists(path):
        shutil.rmtree(path)


def get_function_name():
    return sys._getframe(1).f_code.co_name  # _getframe()则是自己的名字
