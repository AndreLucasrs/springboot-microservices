package academy.devdojo.course.endpoint.service;

import academy.devdojo.core.model.Course;
import academy.devdojo.core.repository.CourseRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @_(@Autowired))
public class CourseService {
    private final CourseRepository
            courseRepository;

    public Iterable<Course> list(Pageable pageable) {
        log.info("List all");
        return courseRepository.findAll(pageable);
    }
}
