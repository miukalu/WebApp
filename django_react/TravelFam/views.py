from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.http import Http404
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import User, Family, FamilyMember, FamilyRequests, Place, Reviews, Trip, TripPlace
from .serializers import (UserRegistrationSerializer, UserSerializer, FamilySerializer, FamilyMemberSerializer, FamilyRequestSerializer,
                          PlaceSerializer, ReviewSerializer, TripSerializer, UserLogoutSerializer, ChangePasswordSerializer)

class UserLoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]

class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer

class UserLogoutView(generics.GenericAPIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'status': 'logged out'}, status=status.HTTP_200_OK)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    lookup_url_kwarg = 'user_id'

    def retrieve(self, request, *args, **kwargs):
        user = get_object_or_404(User, id=self.kwargs['user_id'])
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        user = get_object_or_404(User, id=self.kwargs['user_id'])
        if 'email' in request.data or 'password' in request.data:
            return Response(
                {"error": "Email and password cannot be changed here"},
                status=status.HTTP_400_BAD_REQUEST
            )
        valid_fields = {'login', 'full_name', 'preferences'}
        invalid_fields = set(request.data.keys()) - valid_fields
        if invalid_fields:
            return Response(
                {"error": f"Invalid fields to update: {', '.join(invalid_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        model_fields = {field.name for field in User._meta.get_fields()}
        non_existent_fields = set(request.data.keys()) - model_fields
        if non_existent_fields:
            return Response(
                {"error": f"Fields do not exist in User model: {', '.join(non_existent_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def change_password(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not user.check_password(serializer.validated_data['current_password']):
            return Response({'error': 'current password is incorrect'},
                            status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'status': 'password changed'},
                        status=status.HTTP_200_OK)

class FamilyViewSet(viewsets.ModelViewSet):
    queryset = Family.objects.all()
    serializer_class = FamilySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

class FamilyMemberViewSet(viewsets.ModelViewSet):
    queryset = FamilyMember.objects.all()
    serializer_class = FamilyMemberSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        family_id = self.kwargs.get('family_id')
        if self.request.user.is_superuser:
            return FamilyMember.objects.filter(family_id=family_id)
        if not FamilyMember.objects.filter(
                family_id=family_id,
                user=self.request.user
        ).exists():
            raise PermissionDenied("You are not a member of this family")

        return FamilyMember.objects.filter(family_id=family_id)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, obj)
        return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        current_user_member = get_object_or_404(FamilyMember, user=request.user, family_id=self.kwargs.get('family_id'))
        if request.user.is_superuser:
            pass
        elif current_user_member.role == 'creator':
            pass
        elif instance.user != request.user:
            raise PermissionDenied("You can only remove yourself from the family")

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class FamilyRequestViewSet(viewsets.ModelViewSet):
    queryset = FamilyRequests.objects.all()
    serializer_class = FamilyRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        family_id = self.kwargs.get('family_id')
        if family_id:
            return self.queryset.filter(family_id=family_id)
        return self.queryset.none()

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None, *args, **kwargs):
        family_id = self.kwargs.get('family_id')
        user_id = self.kwargs.get('user_id')
        role = request.data.get('role', 'member')
        family = get_object_or_404(Family, pk=family_id)
        user = get_object_or_404(User, pk=user_id)
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        request_obj.status = FamilyRequests.ACCEPTED
        request_obj.save()
        member, created = FamilyMember.objects.update_or_create(
            user_id=user_id,
            family_id=family_id,
            defaults={'role': role}
            # role=role
        )
        return Response({'status': 'request accepted'},
                        status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def decline(self, request, pk=None, *args, **kwargs):
        family_id = self.kwargs.get('family_id')
        user_id = self.kwargs.get('user_id')
        family = get_object_or_404(Family, pk=family_id)
        user = get_object_or_404(User, pk=user_id)
        request_obj = get_object_or_404(
            FamilyRequests,
            family_id=family_id,
            user_id=user_id,
            status=FamilyRequests.PENDING
        )
        request_obj.status = FamilyRequests.DECLINED
        request_obj.save()
        return Response(
            {'status': 'request declined'},
            status=status.HTTP_200_OK
        )

class PlaceViewSet(viewsets.ModelViewSet):
    queryset = Place.objects.all()
    serializer_class = PlaceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Reviews.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if 'place_id' in self.kwargs:
            return Reviews.objects.filter(place_id=self.kwargs['place_id'])
        return super().get_queryset()
    def perform_create(self, serializer):
        if 'place_id' in self.kwargs:
            serializer.save(
                user=self.request.user,
                place_id=self.kwargs['place_id']
            )
        else:
            serializer.save(user=self.request.user)


class TripViewSet(viewsets.ModelViewSet):
    queryset = Trip.objects.all()
    serializer_class = TripSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    @action(detail=True, methods=['post'])
    def repeat(self, request, pk=None):
        original_trip = self.get_object()
        if not original_trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        new_trip = Trip.objects.create(
            name=f"{original_trip.name} (Copy)",
            country=original_trip.country,
            city=original_trip.city,
            start_date=original_trip.start_date,
            end_date=original_trip.end_date,
            family=original_trip.family,
            family_member=FamilyMember.objects.get(
                user=request.user,
                family=original_trip.family
            ),
            status='planned'
        )
        for trip_place in original_trip.trip_places.all():
            TripPlace.objects.create(
                trip=new_trip,
                place=trip_place.place
            )
        return Response(
            self.get_serializer(new_trip).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def add_place(self, request, pk=None):
        trip = self.get_object()
        place_id = request.data.get('place_id')
        if not place_id:
            return Response(
                {"error": "place_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        place = get_object_or_404(Place, id=place_id)
        TripPlace.objects.get_or_create(trip=trip, place=place)
        return Response(
            {"status": "Place added"},
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['delete'])
    def remove_place(self, request, pk=None):
        trip = self.get_object()
        place_id = request.data.get('place_id')
        if not place_id:
            return Response(
                {"error": "place_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not trip.family.familymember_set.filter(user=request.user).exists():
            return Response(
                {"error": "You are not a member of this family"},
                status=status.HTTP_403_FORBIDDEN
            )
        place = get_object_or_404(Place, id=place_id)
        TripPlace.objects.filter(trip=trip, place=place).delete()
        return Response(
            status=status.HTTP_204_NO_CONTENT
        )

    @action(detail=True, methods=['get'])
    def places(self, request, pk=None):
        trip = self.get_object()
        trip_places = TripPlace.objects.filter(trip=trip).select_related('place')
        serializer = PlaceSerializer([tp.place for tp in trip_places], many=True)
        return Response(serializer.data)

class UserFamiliesView(generics.ListAPIView):
    serializer_class = FamilySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        user = get_object_or_404(User, pk=user_id)
        return Family.objects.filter(familymember__user=user)

class UserTripsView(generics.ListAPIView):
    serializer_class = TripSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        user = get_object_or_404(User, pk=user_id)
        return Trip.objects.filter(family__familymember__user=user)

class PlaceFilterView(generics.ListAPIView):
    serializer_class = PlaceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        category = self.request.query_params.get('category')
        if category:
            places = Place.objects.filter(category__icontains=category)
            if not places.exists():
                raise Http404("Category does not exist")
            return places
        return Place.objects.all()

class ReviewFilterView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        mark = self.request.query_params.get('mark')
        if mark:
            reviews = Reviews.objects.filter(mark=mark)
            if not reviews.exists():
                raise Http404("Reviews does not exist")
            return reviews
        return Reviews.objects.all()