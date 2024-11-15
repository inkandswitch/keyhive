use std::{cell::RefCell, collections::HashSet, rc::Rc};

use futures::future::LocalBoxFuture;

use crate::{IoTaskId, OutboundRequestId, OutgoingResponse, StoryId, StoryResult, Task};

pub(crate) struct ActiveTask {
    pub(crate) future: LocalBoxFuture<'static, TaskResult>,
    pub(crate) data: Rc<RefCell<TaskData>>,
}

// TODO: come up with a better name, something which indicates that this is used
// to coordinate around the suspended operations a task wants to perform
pub(crate) struct TaskData {
    pub(crate) id: Task,
    pub(crate) pending_operations: RefCell<HashSet<OperationDescriptor>>,
}

impl ActiveTask {
    pub(crate) fn new<I: Into<Task>>(id: I, fut: LocalBoxFuture<'static, TaskResult>) -> Self {
        let id = id.into();
        Self {
            future: fut,
            data: Rc::new(RefCell::new(TaskData {
                id,
                pending_operations: RefCell::new(HashSet::new()),
            })),
        }
    }
}

pub(crate) enum TaskResult {
    Request(OutgoingResponse),
    Story(StoryId, StoryResult),
    Spawn,
    OutboundListens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OperationDescriptor {
    Load(IoTaskId),
    LoadRange(IoTaskId),
    Put(IoTaskId),
    Delete(IoTaskId),
    Request(OutboundRequestId),
}
