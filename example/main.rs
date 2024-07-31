enum Shape {
    Triangle,
    Rectangle,
    Circle,
}

struct Rectangle {
    width: u32,
    height: u32,
    shape: Shape,
}

impl Rectangle {
    fn area(&self) -> u32 {   
        self.width * self.height
    }

    fn add_width(&mut self, width: u32) {
        self.width += width;
    }

    fn add_height(&mut self, height: u32) {
        self.height += height;
    }
}

mod constants {
    pub const ANGLE: i64 = 90;
}

fn main() {
    println!("Hello, world!");
    
    let mut rect = Rectangle {
        width: 30,
        height: 50,
        shape: Shape::Circle,
    };

    let fav_shape = match rect.shape {
        Shape::Triangle => "triangle",
        Shape::Rectangle => "rectangle",
        Shape::Circle => "circle",
    };

    println!("Old Area: {}", rect.area());

    for i in 0..10 {
        if i > 5 {
            rect.add_height(50);
            rect.add_width(50);
            rect.width += 50;
            rect.height += 50;
            println!("New Area: {}", rect.area());
        }
    }
    
    println!("New Area: {}", rect.area());
    println!("Favorite shape: {}, Favorite angle: {}", fav_shape, constants::ANGLE);
}
