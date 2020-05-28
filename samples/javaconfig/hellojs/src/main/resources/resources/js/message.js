function Message(data) {
    this.id = ko.observable(data.id)
    this.text = ko.observable(data.text)
    this.summary = ko.observable(data.summary)
    this.created = ko.observable(new Date(data.created))
}

function MessageListViewModel() {
    var self = this;
    self.messages = ko.observableArray([]);
    self.chosenMessageData = ko.observable();
    self.inbox = ko.observable();
    self.compose = ko.observable();
    self.errors = ko.observableArray([]);

    self.goToMessage = function(message) {
        self.inbox(null);
        $.getJSON("./" + message.id(), function(data) {
            self.chosenMessageData(new Message(data));
        });
    };

    self.goToCompose = function(data) {
        self.inbox(null);
        self.chosenMessageData(null);
        self.compose(new Message([]));
    };

    self.goToInbox = function() {
        $.getJSON("./", function(allData) {
            var mappedMessages = $.map(allData, function(item) { return new Message(item) });
            self.messages(mappedMessages);
            self.inbox(mappedMessages);
            self.chosenMessageData(null);
            self.compose(null);
        });
    }

    self.save = function() {
        $.ajax("./", {
            data: ko.toJSON(self.compose),
            type: "post", contentType: "application/json",
            success: function() {
                self.goToInbox();
            }
        });
    };

    self.goToInbox();
}

$(function () {
  var messageModel = new MessageListViewModel();
  var token = $("meta[name='_csrf']").attr("content");
  var header = $("meta[name='_csrf_header']").attr("content");
  $(document).ajaxSend(function(e, xhr, options) {
    messageModel.errors.removeAll();
    xhr.setRequestHeader( "Content-type", "application/json" );
    xhr.setRequestHeader(header, token);
  });
  $(document).ajaxError(function( event, jqxhr, settings, exception ) {
    if (jqxhr.status == 401 ) {
      window.location = "./login";
    } else if(jqxhr.status == 400) {
      var errors = $.parseJSON(jqxhr.responseText);
      for (var i = 0; i < errors.length; i++) {
        messageModel.errors.push(errors[i]);
      }
    } else {
      alert("Error processing "+ settings.url);
    }
  });
  ko.applyBindings(messageModel)
});

