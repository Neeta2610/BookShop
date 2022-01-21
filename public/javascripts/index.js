/* eslint-disable prefer-arrow-callback, no-var, no-tabs */
$(document).ready(function () {
  // Add specific code to this theme here
  // $(".carousel").swipe({

  //   swipe: function (event, direction, distance, duration, fingerCount, fingerData) {

  //     if (direction == 'left') $(this).carousel('next');
  //     if (direction == 'right') $(this).carousel('prev');

  //   },
  //   allowPageScroll: "vertical"
  // });

  //Product Details image slider
  // $('#etalage').etalage({
  //   smallthumbs_position: 'left',
  //   thumb_image_width: 320,
  //   thumb_image_height: 420,
  //   source_image_width: 900,
  //   source_image_height: 1100
  // });

  // $('#etalage1').etalage({
  //   thumb_image_width: 300,
  //   thumb_image_height: 250,
  // });


  function addBlur() {
    $('#background').addClass('blur');
    $('#content').addClass('blur');
  }

  function removeBlur() {
    $('#background').removeClass('blur');
    $('#content').removeClass('blur');
  }

  // var submit = document.getElementById('customerSave', 'addressSave', 'passwordSave');
  // submit.addEventListener('click', clicked);
  // submit.addEventListener('click', validate);
  
  // Account Page Popups
  $('#editDetails').click(function () {
    $('#detailsForm').fadeToggle();
    addBlur();
  });
  $('#editAddress').click(function () {
    $('#addressForm').fadeToggle();
    addBlur();
  });
  $('#orderDetails').click(function () {
    $('#orderForm').fadeToggle();
    addBlur();
  });
  $('#passwordDetails').click(function () {
    $('#passwordForm').fadeToggle();
    addBlur();
  });
  $('#newsletterDetails').click(function () {
    $('#newsletterForm').fadeToggle();
    addBlur();
  });
  $(document).mouseup(function (e) {
    var container = $("#addressForm, #orderForm, #passwordForm, #newsletterForm, #detailsForm");

    if (!container.is(e.target) // if the target of the click isn't the container...
      &&
      container.has(e.target).length === 0) // ... nor a descendant of the container
    {
      container.fadeOut();
      removeBlur();
    }
    $('.close-button').click(function (e) {
      container.fadeOut();
      removeBlur();
      e.stopPropagation();
    });
  });
  $('.password-show').on('click',function(e) {
    if(e.currentTarget.form[1].type == 'password'){
      e.currentTarget.form[1].type = 'text';
    }
    else{
      e.currentTarget.form[1].type = 'password';
    }
  });
  $(".btn1").on('click', function () {
    $(".form-signin").toggleClass("form-signin-left");
    $(".form-signup").toggleClass("form-signup-left");
    $(".frame").toggleClass("frame-long");
    $(".signup-inactive").toggleClass("signup-active");
    $(".signin-active").toggleClass("signin-inactive");
    $(".forgot").toggleClass("forgot-left");
    $(this).removeClass("idle").addClass("active");
  });

  $(".btn1-signup").on('click', function () {
    $("frame.nav").toggleClass("nav-up");
    $(".form-signup-left").toggleClass("form-signup-down");
    $(".success").toggleClass("success-left");
    $(".frame").toggleClass("frame-short");
  });

  $(".btn1-signin").on('click', function () {
    $(".btn1-animate").toggleClass("btn1-animate-grow");
    $(".welcome").toggleClass("welcome-left");
    $(".cover-photo").toggleClass("cover-photo-down");
    $(".frame").toggleClass("frame-short");
    $(".profile-photo").toggleClass("profile-photo-down");
    $(".btn1-goback").toggleClass("btn1-goback-up");
    $(".forgot").toggleClass("forgot-fade");
  });

});