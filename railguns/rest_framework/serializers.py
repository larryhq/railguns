from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_jwt.serializers import jwt_encode_handler, jwt_payload_handler


class DownloadUrlSerializer(serializers.Serializer):
    url = serializers.CharField()


class UploadParamsSerializer(serializers.Serializer):
    key = serializers.CharField()
    AWSAccessKeyId = serializers.CharField()
    OSSAccessKeyId = serializers.CharField()
    acl = serializers.CharField()
    success_action_status = serializers.CharField()
    ContentType = serializers.CharField()
    policy = serializers.CharField()
    signature = serializers.CharField()
    ContentEncoding = serializers.CharField()
    domain = serializers.CharField()


class UserCreatedSerializer(serializers.ModelSerializer):
    token = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    ebank_card_status = serializers.SerializerMethodField()

    class Meta:
        model = get_user_model()
        exclude = ('password', 'is_superuser', 'is_staff', 'date_joined', 'groups', 'user_permissions', 'is_active', 'last_login')

    def get_token(self, obj):
        return jwt_encode_handler(jwt_payload_handler(obj))

    def get_type(self, obj):
        USER_TYPE_CHOICES = ((0, '普通帐户'), (1, '企业帐户'), (2, '企业员工'))
        type_list = [i[1] for i in USER_TYPE_CHOICES if i[0] == obj.type]
        if len(type_list) != 0:
            return {'code': obj.type, 'message': type_list[0]}
        else:
            return {'code': 0, 'message': ''}

    def get_ebank_card_status(self, obj):
        EBANK_STATUS = ((0, ''), (10, '已受理'), (50, '正在开通电子账户'), (100, '开户成功'), (200, '设置密码成功'), (-10, '实名认证失败'), (-100, '开户失败'))
        status_list = [i[1] for i in EBANK_STATUS if i[0] == obj.ebank_card_status]
        return {'code': obj.ebank_card_status,
                'message': '' if status_list == [] else status_list[0]}


class UserPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('password',)

    def validate_password(self, value):
        if len(value) < 6:
            raise ValidationError('password length must more than 6')
        return value
