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
    def create(self, validated_data):
        user = self.context['request'].user
        family = Family.objects.create(**validated_data)
        FamilyMember.objects.create(
            user=user,
            family=family,
            role='creator'
         )
        return family

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
        fields = ['id', 'name', 'country', 'city', 'start_date', 'end_date', 'family', 'family_member', 'status', 'places']
        read_only_fields = ['family_member']

    def create(self, validated_data):
        request = self.context['request']
        family = validated_data['family']
        try:
            family_member = FamilyMember.objects.get(
                user=request.user,
                family=family
            )
        except FamilyMember.DoesNotExist:
            raise serializers.ValidationError("You are not a member of this family")
        validated_data['family_member'] = family_member
        return super().create(validated_data)