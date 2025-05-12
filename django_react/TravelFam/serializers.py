from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Family, FamilyMember, FamilyRequests, Place, Reviews, Trip

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['email', 'login', 'full_name', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            login=validated_data['login'],
            full_name=validated_data['full_name'],
            password=validated_data['password']
        )
        return user

class UserLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except Exception as e:
            raise serializers.ValidationError("Invalid token")

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'login', 'full_name', 'preferences']

class FamilySerializer(serializers.ModelSerializer):
    class Meta:
        model = Family
        fields = ['id', 'name', 'create_date']

class FamilyMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyMember
        fields = ['id', 'user', 'family', 'role']


class FamilyRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyRequests
        fields = ['id', 'user', 'status']

    def create(self, validated_data):

        validated_data['family_id'] = self.context['view'].kwargs['family_id']
        return super().create(validated_data)

class PlaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Place
        fields = ['id', 'coordinates', 'name', 'cost', 'category', 'description']

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reviews
        fields = ['id', 'user', 'place', 'mark', 'text']

class TripSerializer(serializers.ModelSerializer):
    class Meta:
        model = Trip
        fields = ['id', 'name', 'country', 'city', 'start_date', 'end_date', 'family_member', 'family', 'status']