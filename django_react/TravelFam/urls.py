from django.urls import path, include
from rest_framework.routers import DefaultRouter
from TravelFam import views
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register(r'user', views.UserViewSet, basename='user')
router.register(r'family', views.FamilyViewSet, basename='family')
router.register(r'family-member', views.FamilyMemberViewSet, basename='family-member')
router.register(r'family-request', views.FamilyRequestViewSet, basename='family-request')
router.register(r'place', views.PlaceViewSet, basename='place')
router.register(r'review', views.ReviewViewSet, basename='review')
router.register(r'trip', views.TripViewSet, basename='trip')

urlpatterns = [
                  path('api/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),

                  path('api/register/', views.UserRegistrationView.as_view(), name='register'),
                  path('api/login/', views.UserLoginView.as_view(), name='login'),
                  path('api/user/<int:user_id>/change-password/',
                       views.UserViewSet.as_view({'post': 'change_password'}), name='change-password'),
                  path('api/logout/', views.UserLogoutView.as_view(), name='logout'),

                  path('api/user/<int:user_id>/', views.UserViewSet.as_view({'get': 'retrieve', 'put': 'update'}),
                       name='user-detail'),

                  path('api/family/<int:user_id>/', views.UserFamiliesView.as_view(), name='user-families'),
                  path('api/family/', views.FamilyViewSet.as_view({'post': 'create'}), name='family-create'),
                  path('api/family/<int:family_id>/members/', views.FamilyMemberViewSet.as_view({'get': 'list'}),
                       name='family-members'),
                  path('api/family/<int:family_id>/member/<int:pk>/',
                       views.FamilyMemberViewSet.as_view({'delete': 'destroy'}),
                       name='remove-family-member'),
                  path('api/family/<int:family_id>/request/',
                       views.FamilyRequestViewSet.as_view({'post': 'create', 'get': 'list'}),
                       name='create-family-request'),
                  path('api/family/<int:family_id>/requests/', views.FamilyRequestViewSet.as_view({'get': 'list'}),
                       name='family-requests-list'),
                  path('api/family/<int:family_id>/request/<int:user_id>/accept/',
                       views.FamilyRequestViewSet.as_view({'post': 'accept'}), name='accept-family-request'),
                  path('api/family/<int:family_id>/request/<int:user_id>/decline/',
                       views.FamilyRequestViewSet.as_view({'post': 'decline'}), name='decline-family-request'),

                  path('api/trips/<int:user_id>/', views.UserTripsView.as_view(), name='user-trips'),
                  path('api/trip/<int:pk>/', views.TripViewSet.as_view({'get': 'retrieve'}), name='trip-detail'),
                  path('api/trip/<int:pk>/repeat/', views.TripViewSet.as_view({'post': 'repeat'}),
                       name='repeat-trip'),

                  path('api/places/', views.PlaceViewSet.as_view({'get': 'list', 'post': 'create'}),
                       name='places-list'),
                  path('api/places/filter/', views.PlaceFilterView.as_view(), name='places-filter'),
                  path('api/place/<int:place_id>/reviews/',
                       views.ReviewViewSet.as_view({'post': 'create', 'get': 'list'}), name='place-reviews'),

                  path('api/trip/<int:pk>/add_place/', views.TripViewSet.as_view({'post': 'add_place'}),
                       name='trip-add-place'),
                  path('api/trip/<int:pk>/remove_place/', views.TripViewSet.as_view({'delete': 'remove_place'}),
                       name='trip-remove-place'),
                  path('api/trip/<int:pk>/places/', views.TripViewSet.as_view({'get': 'places'}),
                       name='trip-places-list'),

                  path('api/reviews/', views.ReviewViewSet.as_view({'get': 'list'}), name='reviews-list'),
                  path('api/reviews/filter/', views.ReviewFilterView.as_view(), name='reviews-filter'),
                  path('api/reviews/<int:pk>/', views.ReviewViewSet.as_view({'get': 'retrieve'}),
                       name='review-detail'),

                  path('register/', views.register_view, name='register'),
                  path('login/', views.login_view, name='login'),
                  path('logout/', views.logout_view, name='logout'),
                  path('profile/', views.profile_view, name='profile'),
                  path('change-password/', views.change_password_view, name='change-password'),
                  path('update-profile/', views.update_profile_view, name='update-profile'),
                  path('families/', views.families_view, name='families'),
                  path('family/<int:family_id>/members/', views.family_members_view, name='family-members'),
                  path('create-family/', views.create_family_view, name='create-family'),
                  path('trips/', views.trips_view, name='trips'),
                  path('trips/create-trip/', views.create_trip_view, name='create-trip'),
                  path('trip/<int:trip_id>/repeat/', views.repeat_trip_custom_view, name='repeat-trip'),
                  path('trip/<int:trip_id>/details/', views.trip_details_view, name='trip-details'),
                  path('trip/<int:trip_id>/delete/', views.delete_trip_view, name='delete-trip'),
                  path('trip/<int:trip_id>/add-place/', views.trip_add_place_view, name='trip-add-place'),
                  path('trip/<int:trip_id>/remove-place/<int:place_id>/', views.trip_remove_place_view,
                       name='trip-remove-place'),
                  path('places/', views.places_view, name='places'),
                  path('place/<int:place_id>/reviews/', views.place_reviews_view, name='place-reviews'),
                  path('reviews/', views.reviews_view, name='reviews'),
                  path('reviews/create/', views.create_review_view, name='create-review'),
              ] + router.urls
