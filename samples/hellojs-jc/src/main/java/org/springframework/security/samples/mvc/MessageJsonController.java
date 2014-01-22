package org.springframework.security.samples.mvc;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.samples.data.Message;
import org.springframework.security.samples.data.MessageRepository;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping(value = "/", produces="application/json")
public class MessageJsonController {
    private MessageRepository messageRepository;

    @Autowired
    public MessageJsonController(MessageRepository messageRepository) {
        this.messageRepository = messageRepository;
    }

    @RequestMapping
    public ResponseEntity<Iterable<Message>> list() {
        Iterable<Message> messages = messageRepository.findAll();
        return new ResponseEntity<Iterable<Message>>(messages, HttpStatus.OK);
    }

    @RequestMapping("{id}")
    public ResponseEntity<Message> view(@PathVariable Long id) {
        Message message = messageRepository.findOne(id);
        return new ResponseEntity<Message>(message, HttpStatus.OK);
    }

    @RequestMapping(method=RequestMethod.POST, consumes="application/json")
    public ResponseEntity<?> create(@Valid @RequestBody Message message, BindingResult result, RedirectAttributes redirect) {
        if(result.hasErrors()) {
            List<String> errors = new ArrayList<String>(result.getErrorCount());
            for(ObjectError r : result.getAllErrors()) {
                errors.add(r.getDefaultMessage());
            }
            return new ResponseEntity<List<String>>(errors, HttpStatus.BAD_REQUEST);
        }
        message = messageRepository.save(message);
        return new ResponseEntity<Message>(message,HttpStatus.OK);
    }
}
