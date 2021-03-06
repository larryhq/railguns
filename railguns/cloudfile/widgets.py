import os

from django.conf import settings
from django.urls import reverse
from django.forms import widgets
from django.utils.safestring import mark_safe


class CloudFileWidget(widgets.TextInput):

    html = (
        '<div class="s3direct" data-policy-url="{policy_url}">'
        '  <a class="file-link" target="_blank" href="{file_url}">{file_name}</a>'
        '  <a class="file-remove" href="#remove">移除</a>'
        '  <input class="file-url" type="hidden" value="{file_url}" id="{element_id}" name="{name}" />'
        '  <input class="file-input" type="file" />'
        '  <div class="progress progress-striped active">'
        '    <div class="bar"></div>'
        '  </div>'
        '</div>'
    )

    class Media:
        js = (
            'cloudfile/js/scripts.js',
        )
        css = {
            'all': (
                's3direct/css/bootstrap-progress.min.css',
                's3direct/css/styles.css',
            )
        }

    def __init__(self, *args, **kwargs):
        super(CloudFileWidget, self).__init__(*args, **kwargs)

    def render(self, name, value, attrs=None):
        output = self.html.format(
            policy_url=reverse('upload_params', args=['oss']) + '?bucket={}'.format(settings.BUCKET_MEDIA),
            element_id=self.build_attrs(attrs).get('id'),
            file_name=os.path.basename(value or ''),
            file_url=value or '',
            name=name)

        return mark_safe(output)
